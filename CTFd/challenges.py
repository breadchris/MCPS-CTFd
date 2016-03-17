from flask import current_app as app, render_template, request, redirect, abort, jsonify, json as json_mod, url_for, session, Blueprint

from CTFd.utils import ctftime, view_after_ctf, authed, unix_time, get_kpm, can_view_challenges, is_admin, get_config
from CTFd.models import db, Challenges, Files, Solves, WrongKeys, Keys, Evidence, EvidenceConnection, TeamEvidence, TeamEvidenceConnection

from sqlalchemy import or_, and_

import time
import re
import logging
import json

challenges = Blueprint('challenges', __name__)


@challenges.route('/challenges', methods=['GET'])
def challenges_view():
    if not is_admin():
        if not ctftime():
            if view_after_ctf():
                pass
            else:
                return redirect('/')
    if can_view_challenges():
        return render_template('chals.html', ctftime=ctftime())
    else:
        return redirect(url_for('auth.login', next='challenges'))

@challenges.route('/getevidence', methods=['GET'])
def getevidence():
    data = {"nodes":[], "links":[]}

    evidence = TeamEvidence.query.filter_by(teamid=session['id']).all()
    for e in evidence:
        data["nodes"].append({"name": e.name, "group": e.type})

    connections = TeamEvidenceConnection.query.filter_by(teamid=session['id']).all()
    for c in connections:
        src_idx = -1
        dst_idx = -1
        for n, e in enumerate(evidence):
            if e.id == c.had:
                src_idx = n
            elif e.id == c.found:
                dst_idx = n
        if src_idx != -1 and dst_idx != -1:
            data["links"].append({"source": src_idx, "target": dst_idx, "value": 10})

    return json.dumps(data)

@challenges.route('/addevidence', methods=['POST'])
def addevidence():
    if not ctftime():
        if view_after_ctf():
            pass
        else:
            return redirect('/')

    error = {}
    if 'flag' in request.form.keys():
        flag = str(request.form['flag'])
        try:
            print flag
        except:
            pass
        submitted_flags = TeamEvidence.query.filter_by(teamid=session['id'], name=flag).first()
        actual_flags = Evidence.query.filter_by(flag=flag).first()

        if submitted_flags != None:
            error["error"] = "Already submitted flag"
        elif actual_flags == None:
            error["error"] = "Incorrect flag given"
            error["confirm"] = "confirm"
        else:
            new_evidence = TeamEvidence(session["id"], actual_flags.name, 1)
            db.session.add(new_evidence)
            db.session.commit()
    else:
        error["error"] = "No name or flag given"

    return json.dumps(error)

@challenges.route('/confirmevidence', methods=['POST'])
def confirmevidence():
    if not ctftime():
        if view_after_ctf():
            pass
        else:
            return redirect('/')

    error = {}
    if 'flag' in request.form.keys():
        flag = str(request.form['flag'])
        submitted_flags = TeamEvidence.query.filter_by(teamid=session['id'], name=flag).first()

        if submitted_flags != None:
            error["error"] = "Already submitted evidence"
        else:
            db.session.add(TeamEvidence(session["id"], flag, 2))
            db.session.commit()
    else:
        error["error"] = "No name or flag given"

    return json.dumps(error)

@challenges.route('/removeevidence', methods=['POST'])
def removeevidence():
    if not ctftime():
        if view_after_ctf():
            pass
        else:
            return redirect('/')
    error = {}
    if 'evidence-name' in request.form.keys():
        evidence_name = str(request.form['evidence-name'])
        submitted_flags = TeamEvidence.query.filter_by(teamid=session['id'], name=evidence_name).first()
        submitted_connections = TeamEvidenceConnection.query.filter(and_(\
            or_(TeamEvidenceConnection.had == evidence_name, TeamEvidenceConnection.found == evidence_name \
                ), TeamEvidenceConnection.teamid == session['id'])).all()

        if submitted_flags == None:
            error["error"] = "Evidence does not exist"
        else:
            db.session.delete(submitted_flags)
            for c in submitted_connections:
                db.session.delete(c)
            db.session.commit()

    else:
        error["error"] = "No name or flag given"

    return json.dumps(error)

@challenges.route('/addconnection', methods=['POST'])
def addconnection():
    if not ctftime():
        if view_after_ctf():
            pass
        else:
            return redirect('/')
    error = {}
    if 'evidence-name1' in request.form.keys() and 'evidence-name1' in request.form.keys():
        evidence_name1 = str(request.form['evidence-name1'])
        evidence_name2 = str(request.form['evidence-name2'])

        has_evidence_name1 = TeamEvidence.query.filter_by(teamid=session['id'], name=evidence_name1).first()
        has_evidence_name2 = TeamEvidence.query.filter_by(teamid=session['id'], name=evidence_name2).first()

        if has_evidence_name1 == None or has_evidence_name2 == None:
            if has_evidence_name1 == None:
                error["error"] = "Evidence name 1 does not exist"
            elif has_evidence_name2 == None:
                error["error"] = "Evidence name 2 does not exist"
        else:
            submitted_connections = TeamEvidenceConnection.query.filter_by(teamid=session['id'], \
                had=has_evidence_name1.id, found=has_evidence_name2.id).first()

            if submitted_connections != None:
                error["error"] = "Connection already exists"
            else:
                db.session.add(TeamEvidenceConnection(session["id"], has_evidence_name1.id, has_evidence_name2.id))
                db.session.commit()

    else:
        error["error"] = "No evidence given"

    return json.dumps(error)

@challenges.route('/removeconnection', methods=['POST'])
def removeconnection():
    if not ctftime():
        if view_after_ctf():
            pass
        else:
            return redirect('/')
    error = {}
    if 'evidence-name1' in request.form.keys() and 'evidence-name1' in request.form.keys():
        evidence_name1 = str(request.form['evidence-name1'])
        evidence_name2 = str(request.form['evidence-name2'])

        has_evidence_name1 = TeamEvidence.query.filter_by(teamid=session['id'], name=evidence_name1).first()
        has_evidence_name2 = TeamEvidence.query.filter_by(teamid=session['id'], name=evidence_name2).first()

        if has_evidence_name1 == None or has_evidence_name2 == None:
            if has_evidence_name1 == None:
                error["error"] = "Evidence name 1 does not exist"
            elif has_evidence_name2 == None:
                error["error"] = "Evidence name 2 does not exist"
        else:
            submitted_connections = TeamEvidenceConnection.query.filter_by(teamid=session['id'], \
                had=has_evidence_name1.id, found=has_evidence_name2.id).first()

            if submitted_connections == None:
                error["error"] = "Connection does not exist"
            else:
                db.session.delete(submitted_connections)
                db.session.commit()

    else:
        error["error"] = "No evidence given"

    return json.dumps(error)

@challenges.route('/chals', methods=['GET'])
def chals():
    if not is_admin():
        if not ctftime():
            if view_after_ctf():
                pass
            else:
                return redirect('/')
    if can_view_challenges():
        chals = Challenges.query.add_columns('id', 'name', 'value', 'description', 'category').order_by(Challenges.value).all()

        json = {'game':[]}
        for x in chals:
            files = [ str(f.location) for f in Files.query.filter_by(chal=x.id).all() ]
            json['game'].append({'id':x[1], 'name':x[2], 'value':x[3], 'description':x[4], 'category':x[5], 'files':files})

        db.session.close()
        return jsonify(json)
    else:
        db.session.close()
        return redirect(url_for('auth.login', next='chals'))


@challenges.route('/chals/solves')
def chals_per_solves():
    if can_view_challenges():
        solves = Solves.query.add_columns(db.func.count(Solves.chalid)).group_by(Solves.chalid).all()
        json = {}
        for chal, count in solves:
            json[chal.chal.name] = count
        return jsonify(json)
    return redirect(url_for('auth.login', next='chals/solves'))


@challenges.route('/solves')
@challenges.route('/solves/<teamid>')
def solves(teamid=None):
    if teamid is None:
        if authed():
            solves = Solves.query.filter_by(teamid=session['id']).all()
        else:
            abort(401)
    else:
        solves = Solves.query.filter_by(teamid=teamid).all()
    db.session.close()
    json = {'solves':[]}
    for x in solves:
        json['solves'].append({ 'chal':x.chal.name, 'chalid':x.chalid,'team':x.teamid, 'value': x.chal.value, 'category':x.chal.category, 'time':unix_time(x.date)})
    return jsonify(json)


@challenges.route('/maxattempts')
def attempts():
    chals = Challenges.query.add_columns('id').all()
    json = {'maxattempts':[]}
    for chal, chalid in chals:
        fails = WrongKeys.query.filter_by(team=session['id'], chalid=chalid).count()
        if fails >= int(get_config("max_tries")) and int(get_config("max_tries")) > 0:
            json['maxattempts'].append({'chalid':chalid})
    return jsonify(json)


@challenges.route('/fails/<teamid>', methods=['GET'])
def fails(teamid):
    fails = WrongKeys.query.filter_by(team=teamid).count()
    solves = Solves.query.filter_by(teamid=teamid).count()
    db.session.close()
    json = {'fails':str(fails), 'solves': str(solves)}
    return jsonify(json)


@challenges.route('/chal/<chalid>/solves', methods=['GET'])
def who_solved(chalid):
    solves = Solves.query.filter_by(chalid=chalid).order_by(Solves.date.asc())
    json = {'teams':[]}
    for solve in solves:
        json['teams'].append({'id':solve.team.id, 'name':solve.team.name, 'date':solve.date})
    return jsonify(json)


@challenges.route('/chal/<chalid>', methods=['POST'])
def chal(chalid):
    if not ctftime():
        return redirect(url_for('challenges.challenges_view'))
    if authed():
        fails = WrongKeys.query.filter_by(team=session['id'], chalid=chalid).count()
        logger = logging.getLogger('keys')
        data = (time.strftime("%m/%d/%Y %X"), session['username'].encode('utf-8'), request.form['key'].encode('utf-8'), get_kpm(session['id']))
        print("[{0}] {1} submitted {2} with kpm {3}".format(*data))

        # Hit max attempts
        if fails >= int(get_config("max_tries")) and int(get_config("max_tries")) > 0:
            return "4" #too many tries on this challenge

        # Anti-bruteforce / submitting keys too quickly
        if get_kpm(session['id']) > 10:
            wrong = WrongKeys(session['id'], chalid, request.form['key'])
            db.session.add(wrong)
            db.session.commit()
            db.session.close()
            logger.warn("[{0}] {1} submitted {2} with kpm {3} [TOO FAST]".format(*data))
            return "3" # Submitting too fast

        solves = Solves.query.filter_by(teamid=session['id'], chalid=chalid).first()

        # Challange not solved yet
        if not solves:
            chal = Challenges.query.filter_by(id=chalid).first()
            key = str(request.form['key'].strip().lower())
            keys = json.loads(chal.flags)
            for x in keys:
                if x['type'] == 0: #static key
                    print(x['flag'], key.strip().lower())
                    if x['flag'] == key.strip().lower():
                        solve = Solves(chalid=chalid, teamid=session['id'], ip=request.remote_addr, flag=key)
                        db.session.add(solve)
                        db.session.commit()
                        db.session.close()
                        logger.info("[{0}] {1} submitted {2} with kpm {3} [CORRECT]".format(*data))
                        return "1" # key was correct
                elif x['type'] == 1: #regex
                    res = re.match(str(x['flag']), key, re.IGNORECASE)
                    if res and res.group() == key:
                        solve = Solves(chalid=chalid, teamid=session['id'], ip=request.remote_addr, flag=key)
                        db.session.add(solve)
                        db.session.commit()
                        db.session.close()
                        logger.info("[{0}] {1} submitted {2} with kpm {3} [CORRECT]".format(*data))
                        return "1" # key was correct

            wrong = WrongKeys(session['id'], chalid, request.form['key'])
            db.session.add(wrong)
            db.session.commit()
            db.session.close()
            logger.info("[{0}] {1} submitted {2} with kpm {3} [WRONG]".format(*data))
            return '0' # key was wrong

        # Challenge already solved
        else:
            logger.info("{0} submitted {1} with kpm {2} [ALREADY SOLVED]".format(*data))
            return "2" # challenge was already solved
    else:
        return "-1"
