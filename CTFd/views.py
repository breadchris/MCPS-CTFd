from flask import current_app as app, render_template, render_template_string, request, redirect, abort, jsonify, json as json_mod, url_for, session, Blueprint, Response
from CTFd.utils import authed, ip2long, long2ip, is_setup, validate_url, get_config, sha512
from CTFd.models import db, Teams, Solves, Challenges, WrongKeys, Keys, Tags, Files, Tracking, Pages, Config, Evidence, EvidenceConnection

from jinja2.exceptions import TemplateNotFound
from passlib.hash import bcrypt_sha256
from collections import OrderedDict

import logging
import os
import re
import sys
import json
import os

views = Blueprint('views', __name__)


@views.before_request
def tracker():
    if authed():
        if not Tracking.query.filter_by(ip=ip2long(request.remote_addr)).first():
            visit = Tracking(request.remote_addr, session['id'])
            db.session.add(visit)
            db.session.commit()
            db.session.close()


@views.before_request
def csrf():
    if request.method == "POST":
        print(session)
        print(request.form.get('nonce'))
        if session['nonce'] != request.form.get('nonce'):
            abort(403)


@views.before_request
def redirect_setup():
    if request.path == "/static/css/style.css":
        return
    if not is_setup() and request.path != "/setup":
        return redirect(url_for('views.setup'))


@views.route('/setup', methods=['GET', 'POST'])
def setup():
    # with app.app_context():
        # admin = Teams.query.filter_by(admin=True).first()

    if not is_setup():
        if not session.get('nonce'):
            session['nonce'] = sha512(os.urandom(10))
        if request.method == 'POST':
            ctf_name = request.form['ctf_name']
            ctf_name = Config('ctf_name', ctf_name)

            ## CSS
            css = Config('start', '')

            ## Admin user
            name = request.form['name']
            email = request.form['email']
            password = request.form['password']
            admin = Teams(name, email, password)
            admin.admin = True
            admin.banned = True

            ## Index page
            html = request.form['html']
            page = Pages('index', html)

            #max attempts per challenge
            max_tries = Config("max_tries",0)


            ## Start time
            start = Config('start', None)
            end = Config('end', None)

            ## Challenges cannot be viewed by unregistered users
            view_challenges_unregistered = Config('view_challenges_unregistered', None)

            ## Allow/Disallow registration
            prevent_registration = Config('prevent_registration', None)

            setup = Config('setup', True)

            evidence = [
                ["sample1", "Encrypted Zip", "{N3xt_l3v3l_encryption}"],
                ["sample2", "Caesar Cipher Sample", "{c1pherz_are_kewl}"],
                ["police_profile", "Police Profile", "{and_so_1t_begins}"],
                ["caesar_cipher", "Phone Pattern Clue", "{i_love_caesar_sal4ds}"],
                ["gesture_key_hash", "Gesture Key Hash", "{they_were_to0_young_to_d1e}"],
                ["victims_contacts", "Victim's Contacts", "{I_just_w4nt_To_phone_home}"],
                ["victims_history", "Victim's History", "{Back_to_the_H1story}"],
                ["sd_card", "SD Card", "{m0unting_has_never_b33n_3asier}"],
                ["sd_card_hidden", "SD Card Hidden Image", "{h1dden_files_4re_soooooo_s3cret}"],
                ["sd_card_deleted", "SD Card Deleted Image", "{ur_da7a_doesnt_go_away}"],
                ["agents_wallet", "Agents Wallet", "{h3_h3_m3_c01n5_1n_B175}"],
                ["emails", "Victim's Emails", "{7his_15_n0t_th3_3m41l_u_w4nt}"],
                ["hacktivists_website", "Hacktivist's Website", "{t3h_h4ckers_sp4c3}"],
                ["consulting_company_it_portal", "Consulting Company IT Portal", "{SYS_4DM11111111N_P0RTAAAAL}"],
                ["hacktivists_login", "Hacktivist Login", "{h4ck3r5_log1n_700}"],
                ["voting_database_corrupt", "Voting Database", "{17_corrup73d_:-(}"],
                ["personnel_database", "Personnel Database", "{4uthor1zed_per50nnel_0nly}"],
                ["hacktivists_pcap", "Hacktivist's PCAP", "{much_sh3llsh0ck_m4ny_pack3t_7oo_FTP}"],
                ["encrypted_zip", "Encrypted Zip", "{7ooo_much_Encryption_b4d_four_health}"],
                ["construct_qr", "Construct QR Code", "{carpet_weaving_grandmaster}"],
                ["irc_logs", "IRC Logs", "{700_much_3ncrypted_1337_sp3ak}"]
            ]

            for e in evidence:
                exec "{0} = Evidence(\"{1}\", \"{2}\")".format(e[0], e[1], e[2])
                db.session.add(eval(e[0]))
            db.session.commit()

            '''
            connections = [
                [police_profile, victims_phone],
                [police_profile, sd_card],
                [victims_phone, agents_wallet],
                [victims_phone, emails],
                [victims_phone, browser_history],
                [victims_phone, contacts],
                [browser_history, hacktivists_website],
                [browser_history, consulting_company_it_portal],
                [hacktivists_website, hacktivists_login],
                [hacktivists_login, seeded_torrent],
                [hacktivists_login, irc_logs],
                [seeded_torrent, stolen_personnel_database],
                [seeded_torrent, stolen_voting_database],
                [seeded_torrent, hacktivists_pcap],
                [irc_logs, seeded_torrent],
                [consulting_company_it_portal, voting_database_corrupt],
                [consulting_company_it_portal, personnel_database]
            ]

            for c in connections:
                c = [_.eid for _ in c]
                db.session.add(EvidenceConnection(*c))
            db.session.commit()
            '''

            db.session.add(ctf_name)
            db.session.add(admin)
            db.session.add(page)
            db.session.add(max_tries)
            db.session.add(start)
            db.session.add(end)
            db.session.add(view_challenges_unregistered)
            db.session.add(prevent_registration)
            db.session.add(css)
            db.session.add(setup)
            db.session.commit()
            app.setup = False
            return redirect('/')
        print(session.get('nonce'))
        return render_template('setup.html', nonce=session.get('nonce'))
    return redirect('/')


# Custom CSS handler
@views.route('/static/user.css')
def custom_css():
    return Response(get_config("css"), mimetype='text/css')


# Static HTML files
@views.route("/", defaults={'template': 'index'})
@views.route("/<template>")
def static_html(template):
    try:
        return render_template('%s.html' % template)
    except TemplateNotFound:
        page = Pages.query.filter_by(route=template).first()
        if page:
            return render_template_string('{% extends "base.html" %}{% block content %}' + page.html + '{% endblock %}')
        else:
            abort(404)


@views.route('/teams', defaults={'page':'1'})
@views.route('/teams/<page>')
def teams(page):
    page = abs(int(page))
    results_per_page = 50
    page_start = results_per_page * ( page - 1 )
    page_end = results_per_page * ( page - 1 ) + results_per_page

    teams = Teams.query.slice(page_start, page_end).all()
    count = db.session.query(db.func.count(Teams.id)).first()[0]
    print(count)
    pages = int(count / results_per_page) + (count % results_per_page > 0)
    return render_template('teams.html', teams=teams, team_pages=pages)

'''
@views.route('/team/<teamid>', methods=['GET', 'POST'])
def team(teamid):
    user = Teams.query.filter_by(id=teamid).first()
    solves = Solves.query.filter_by(teamid=teamid).all()
    score = user.score()
    place = user.place()
    db.session.close()

    if request.method == 'GET':
        return render_template('team.html', solves=solves, team=user, score=score, place=place)
    elif request.method == 'POST':
        json = {'solves':[]}
        for x in solves:
            json['solves'].append({'id':x.id, 'chal':x.chalid, 'team':x.teamid})
        return jsonify(json)
'''

@views.route('/profile', methods=['POST', 'GET'])
def profile():
    if authed():
        if request.method == "POST":
            errors = []

            name = request.form.get('name')
            email = request.form.get('email')
            website = request.form.get('website')
            affiliation = request.form.get('affiliation')
            country = request.form.get('country')

            user = Teams.query.filter_by(id=session['id']).first()

            if not get_config('prevent_name_change'):
                names = Teams.query.filter_by(name=name).first()
                name_len = len(request.form['name']) == 0

            emails = Teams.query.filter_by(email=email).first()
            valid_email = re.match("[^@]+@[^@]+\.[^@]+", email)

            if ('password' in request.form.keys() and not len(request.form['password']) == 0) and \
                    (not bcrypt_sha256.verify(request.form.get('confirm').strip(), user.password)):
                errors.append("Your old password doesn't match what we have.")
            if not valid_email:
                errors.append("That email doesn't look right")
            if not get_config('prevent_name_change') and names and name!=session['username']:
                errors.append('That team name is already taken')
            if emails and emails.id != session['id']:
                errors.append('That email has already been used')
            if not get_config('prevent_name_change') and name_len:
                errors.append('Pick a longer team name')
            if website.strip() and not validate_url(website):
                errors.append("That doesn't look like a valid URL")

            if len(errors) > 0:
                return render_template('profile.html', name=name, email=email, website=website,
                                       affiliation=affiliation, country=country, errors=errors)
            else:
                team = Teams.query.filter_by(id=session['id']).first()
                if not get_config('prevent_name_change'):
                    team.name = name
                team.email = email
                session['username'] = team.name

                if 'password' in request.form.keys() and not len(request.form['password']) == 0:
                    team.password = bcrypt_sha256.encrypt(request.form.get('password'))
                team.website = website
                team.affiliation = affiliation
                team.country = country
                db.session.commit()
                db.session.close()
                return redirect(url_for('views.profile'))
        else:
            user = Teams.query.filter_by(id=session['id']).first()
            name = user.name
            email = user.email
            website = user.website
            affiliation = user.affiliation
            country = user.country
            prevent_name_change = get_config('prevent_name_change')
            return render_template('profile.html', name=name, email=email, website=website, affiliation=affiliation,
                                   country=country, prevent_name_change=prevent_name_change)
    else:
        return redirect(url_for('auth.login'))
