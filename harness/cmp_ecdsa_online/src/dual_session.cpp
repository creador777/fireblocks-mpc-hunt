#include "opus/dual_session.h"
#include "opus/det_rand.h"
#include "opus/oracles.h"

#include "cosigner/cosigner_exception.h"
#include "cosigner/mpc_globals.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>
#include <stdexcept>

using namespace fireblocks::common::cosigner;

namespace opus {
namespace {

using Clock = std::chrono::steady_clock;

struct call_outcome
{
    bool threw = false;
    bool fatal = false;                 // no es un rechazo limpio de la libreria
    std::string type;
    std::string what;
};

template <typename Fn>
call_outcome guarded(Fn&& fn)
{
    call_outcome o;
    try {
        fn();
    } catch (const cosigner_exception& e) {
        o.threw = true; o.type = "cosigner_exception"; o.what = e.what();
    } catch (const std::out_of_range& e) {
        o.threw = true; o.fatal = true; o.type = "std::out_of_range"; o.what = e.what();
    } catch (const std::exception& e) {
        o.threw = true; o.fatal = true; o.type = "std::exception"; o.what = e.what();
    } catch (...) {
        o.threw = true; o.fatal = true; o.type = "unknown"; o.what = "non-standard exception";
    }
    return o;
}

// Mensajes distintos por ceremonia. Que difieran es la premisa del oraculo de
// nonce: dos firmas con el mismo r sobre el MISMO mensaje son solo un
// duplicado; sobre mensajes distintos revelan la clave privada.
std::vector<uint8_t> ceremony_message(int which)
{
    std::vector<uint8_t> m(32, 0);
    const uint8_t base = static_cast<uint8_t>(which == 0 ? 0xA0 : 0x50);
    for (size_t i = 0; i < m.size(); ++i)
        m[i] = static_cast<uint8_t>((base + i) & 0xFF);
    return m;
}

// Una ceremonia reanudable. El driver de una sola sesion ejecuta las cinco
// rondas dentro de una funcion; para intercalar hay que poder detenerse entre
// ellas, asi que el estado intermedio vive aqui y step() avanza exactamente
// una ronda.
class ceremony
{
public:
    ceremony(int index,
             std::map<uint64_t, std::unique_ptr<player_ctx>>& players,
             const std::string& key_id,
             const std::vector<uint64_t>& signers,
             const std::vector<uint32_t>& path)
        : _index(index), _players(players), _key_id(key_id), _signers(signers),
          _path(path)
    {
        _txid = (index == 0) ? "opus-dual-tx-a" : "opus-dual-tx-b";
        for (uint64_t id : _signers) {
            _players_str.insert(std::to_string(id));
            _players_ids.insert(id);
        }
        memset(_chaincode, 0, sizeof(HDChaincode));

        signing_block_data blk;
        blk.data = ceremony_message(index);
        blk.path = _path;
        _expected_message = blk.data;
        _data.blocks.push_back(std::move(blk));
        memcpy(_data.chaincode, _chaincode, sizeof(HDChaincode));
    }

    const std::string& txid() const { return _txid; }
    int rounds_completed() const { return _round; }
    bool finished() const { return _state != ceremony_state::PENDING &&
                                   _state != ceremony_state::RUNNING; }
    ceremony_state state() const { return _state; }
    const std::vector<recoverable_signature>& sigs() const { return _sigs; }
    const std::vector<uint8_t>& expected_message() const { return _expected_message; }
    const std::vector<uint32_t>& path() const { return _path; }
    const uint8_t* chaincode() const { return _chaincode; }

    ceremony_report report() const
    {
        ceremony_report r;
        r.state = _state;
        r.rounds_completed = _round;
        r.signature_produced = !_sigs.empty();
        r.exception_type = _exception_type;
        r.detail = _detail;
        return r;
    }

    // Avanza UNA ronda. Devuelve false cuando ya no hay nada que avanzar.
    bool step()
    {
        if (finished())
            return false;
        _state = ceremony_state::RUNNING;
        switch (_round) {
        case 0: return round1();
        case 1: return round2();
        case 2: return round3();
        case 3: return round4();
        case 4: return round5();
        default: return false;
        }
    }

private:
    void reject(const call_outcome& o, int round)
    {
        // Una ceremonia de control, sin mutaciones, NO debe ser rechazada:
        // si lo es, el fixture esta mal, no la libreria.
        _state = o.fatal ? ceremony_state::FAULTED : ceremony_state::REJECTED;
        _exception_type = o.type;
        _detail = "round " + std::to_string(round) + " threw";
    }

    bool round1()
    {
        for (uint64_t id : _signers) {
            std::vector<cmp_mta_request> out;
            auto o = guarded([&] {
                _players.at(id)->service.start_signing(
                    _key_id, _txid, static_cast<cosigner_sign_algorithm>(0),
                    _data, "", _players_str, _players_ids, out);
            });
            if (o.threw) { reject(o, 1); return false; }
            _requests[id] = std::move(out);
        }
        _round = 1;
        return true;
    }

    bool round2()
    {
        for (uint64_t id : _signers) {
            auto in = _requests;               // copia: la libreria mueve del input
            cmp_mta_responses out;
            auto o = guarded([&] {
                _players.at(id)->service.mta_response(_txid, in, MPC_PROTOCOL_VERSION, out);
            });
            if (o.threw) { reject(o, 2); return false; }
            _responses[id] = std::move(out);
        }
        _round = 2;
        return true;
    }

    bool round3()
    {
        for (uint64_t id : _signers) {
            auto in = _responses;
            std::vector<cmp_mta_deltas> out;
            auto o = guarded([&] {
                _players.at(id)->service.mta_verify(_txid, in, out);
            });
            if (o.threw) { reject(o, 3); return false; }
            _deltas[id] = std::move(out);
        }
        _round = 3;
        return true;
    }

    bool round4()
    {
        for (uint64_t id : _signers) {
            auto in = _deltas;
            std::vector<elliptic_curve_scalar> out;
            auto o = guarded([&] {
                _players.at(id)->service.get_si(_txid, in, out);
            });
            if (o.threw) { reject(o, 4); return false; }
            _sis[id] = std::move(out);
        }
        _round = 4;
        return true;
    }

    bool round5()
    {
        const uint64_t observer = _signers.front();
        auto in = _sis;
        std::vector<recoverable_signature> out;
        auto o = guarded([&] {
            _players.at(observer)->service.get_cmp_signature(_txid, in, out);
        });
        if (o.threw) { reject(o, 5); return false; }
        _sigs = std::move(out);
        _round = 5;
        _state = ceremony_state::COMPLETED;
        return true;
    }

    int _index;
    std::map<uint64_t, std::unique_ptr<player_ctx>>& _players;
    std::string _key_id;
    std::vector<uint64_t> _signers;
    std::vector<uint32_t> _path;
    std::string _txid;
    std::set<std::string> _players_str;
    std::set<uint64_t> _players_ids;
    signing_data _data;
    HDChaincode _chaincode;
    std::vector<uint8_t> _expected_message;

    int _round = 0;
    ceremony_state _state = ceremony_state::PENDING;
    std::string _exception_type;
    std::string _detail;

    std::map<uint64_t, std::vector<cmp_mta_request>> _requests;
    std::map<uint64_t, cmp_mta_responses> _responses;
    std::map<uint64_t, std::vector<cmp_mta_deltas>> _deltas;
    std::map<uint64_t, std::vector<elliptic_curve_scalar>> _sis;
    std::vector<recoverable_signature> _sigs;
};

// Huella del registro de UN txid en todos los jugadores. Es lo que permite
// afirmar que un paso de B no toco el registro de A sin mirar su contenido.
std::string record_fingerprint(
    const std::map<uint64_t, std::unique_ptr<player_ctx>>& players,
    const std::string& txid)
{
    std::string acc;
    for (const auto& entry : players) {
        acc += std::to_string(entry.first);
        acc += entry.second->signing_store.has(txid) ? ":1" : ":0";
        acc += ",";
    }
    return acc;
}

} // namespace

const char* to_string(ceremony_state s)
{
    switch (s) {
    case ceremony_state::PENDING:   return "PENDING";
    case ceremony_state::RUNNING:   return "RUNNING";
    case ceremony_state::COMPLETED: return "COMPLETED";
    case ceremony_state::REJECTED:  return "REJECTED";
    case ceremony_state::FAULTED:   return "FAULTED";
    }
    return "PENDING";
}

dual_session::dual_session(const snapshot& snap, const std::string& key_id, std::string& err)
    : _key_id(key_id), _snap(snap)
{
    silence_library_logging();
    _ids = snap.player_ids();
    for (uint64_t id : _ids)
        _key_stores[id];
    if (!install_snapshot(snap, key_id, _key_stores, err))
        return;
    _ok = true;
}

dual_result dual_session::run(uint64_t seed, const std::vector<uint8_t>& schedule)
{
    dual_result res;
    const auto t0 = Clock::now();

    if (!_ok) {
        res.harness_fault = true;
        res.detail = "snapshot not installed";
        return res;
    }

    // Conjunto de firmantes: exactamente t jugadores, como exige start_signing.
    std::vector<uint64_t> signers = _ids;
    if (static_cast<size_t>(_snap.t) < signers.size())
        signers.resize(_snap.t);
    if (signers.empty() || signers.size() != static_cast<size_t>(_snap.t)) {
        res.harness_fault = true;
        res.detail = "signer set does not match the snapshot threshold";
        return res;
    }

    reseed_with_label(seed, "dual");

    // UN solo contexto por jugador para las DOS ceremonias. Si cada una
    // tuviera el suyo no compartirian ni store ni plataforma y el intercalado
    // no podria encontrar nada.
    std::map<uint64_t, std::unique_ptr<player_ctx>> players;
    for (uint64_t id : _ids)
        players.emplace(id, std::make_unique<player_ctx>(id, _key_stores.at(id)));

    const std::string key_digest_before = _key_stores.at(signers.front()).digest();

    const std::vector<uint32_t> path{44, 0, 0, 0, 0};
    ceremony a(0, players, _key_id, signers, path);
    ceremony b(1, players, _key_id, signers, path);
    ceremony* cer[2] = {&a, &b};

    int last_turn = -1;
    bool crossed = false;
    size_t cursor = 0;
    // Cota dura: cinco rondas por ceremonia mas margen. Un schedule no puede
    // hacer que esto no termine.
    const int max_steps = 32;

    for (int taken = 0; taken < max_steps; ++taken) {
        if (a.finished() && b.finished())
            break;

        int turn;
        if (cursor < schedule.size()) {
            turn = schedule[cursor++] & 1;
            if (cer[turn]->finished())
                turn = 1 - turn;              // el turno pasa a quien puede usarlo
        } else {
            // Schedule agotado: se completa lo que falte en orden fijo. Dejar
            // una ceremonia a medias inventaria un rechazo que la libreria no
            // produjo.
            turn = a.finished() ? 1 : 0;
        }
        if (cer[turn]->finished())
            break;

        if (last_turn != -1 && turn != last_turn) {
            ++res.interleave_points;
            crossed = true;
        }
        last_turn = turn;

        // Huella del OTRO registro antes y despues del paso: si cambia, un
        // paso de una ceremonia toco el estado de la otra.
        const std::string other_txid = cer[1 - turn]->txid();
        const std::string before = record_fingerprint(players, other_txid);

        res.schedule.push_back(static_cast<uint8_t>(turn));
        const bool advanced = cer[turn]->step();

        if (record_fingerprint(players, other_txid) != before) {
            res.state_isolation = false;
            res.detail = "a step of one ceremony changed the other record";
        }

        if (advanced && crossed)
            ++res.advanced_past_injection;

        res.max_round_reached = std::max(res.max_round_reached,
                                         std::max(a.rounds_completed(), b.rounds_completed()));
    }

    res.a = a.report();
    res.b = b.report();
    res.harness_fault = (a.state() == ceremony_state::FAULTED ||
                         b.state() == ceremony_state::FAULTED);
    res.both_completed = (a.state() == ceremony_state::COMPLETED &&
                          b.state() == ceremony_state::COMPLETED);

    // --- oraculos sobre firmas completas ----------------------------------
    if (res.both_completed && !a.sigs().empty() && !b.sigs().empty()) {
        const recoverable_signature& sa = a.sigs().front();
        const recoverable_signature& sb = b.sigs().front();

        std::string detail;
        const bool va = oracle_signature_valid(_snap, a.expected_message(), a.path(),
                                               a.chaincode(), sa, false, detail);
        const bool vb = oracle_signature_valid(_snap, b.expected_message(), b.path(),
                                               b.chaincode(), sb, false, detail);
        res.signatures_valid = va && vb;

        // Cruzado: la firma de A NO debe verificar el mensaje de B. Que lo
        // hiciera significaria que una sesion firmo lo de la otra.
        std::string ignored;
        const bool cross_ab = oracle_signature_valid(_snap, b.expected_message(), b.path(),
                                                     b.chaincode(), sa, false, ignored);
        const bool cross_ba = oracle_signature_valid(_snap, a.expected_message(), a.path(),
                                                     a.chaincode(), sb, false, ignored);
        res.cross_session_verification = cross_ab || cross_ba;

        // Reutilizacion de nonce. Dos firmas con el mismo r sobre mensajes
        // distintos revelan la clave privada en ECDSA. La comparacion es
        // interna; ni r ni s salen de aqui.
        res.nonce_reuse = (memcmp(sa.r, sb.r, sizeof(sa.r)) == 0);
    }

    // --- rollback: un get_cmp_signature exitoso no deja registro temporal --
    //
    // Solo en el OBSERVADOR. La libreria borra el registro dentro de
    // get_cmp_signature (cmp_ecdsa_online_signing_service.cpp:503), y esa
    // llamada ocurre en un unico jugador; los demas firmantes nunca ejecutan
    // la ronda 5, asi que conservar su registro es lo correcto. Comprobarlo en
    // todos convertia el comportamiento normal en un hallazgo -- lo detecto
    // este control antes de que llegara a producir un falso positivo.
    const uint64_t observer = signers.front();
    if (a.state() == ceremony_state::COMPLETED &&
        players.at(observer)->signing_store.has(a.txid()))
        res.rollback_clean = false;
    if (b.state() == ceremony_state::COMPLETED &&
        players.at(observer)->signing_store.has(b.txid()))
        res.rollback_clean = false;

    res.key_store_unchanged =
        (key_digest_before == _key_stores.at(signers.front()).digest());

    res.elapsed_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count());
    return res;
}

} // namespace opus
