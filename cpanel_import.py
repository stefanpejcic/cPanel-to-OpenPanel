import os
import json
import socket
from flask import Flask, Response, abort, render_template, request, send_file, g, jsonify, session, url_for, flash, redirect, get_flashed_messages
import subprocess
import datetime
import psutil
from app import app, is_license_valid, login_required_route, load_openpanel_config, connect_to_database
import docker

from modules.helpers import get_all_users, get_user_and_plan_count, get_plan_by_id, get_all_plans, get_userdata_by_username, get_hosting_plan_name_by_id, get_user_websites, is_username_unique, gravatar_url

@app.route('/import/cpanel', methods=['GET', 'POST'])
@login_required
def import_cpanel_whm_account():
    if request.method == 'POST':
        path = request.form.get('path')
        plan_name = request.form.get('plan_name')

        if not path or not plan_name:
            flash('Path and Plan name are required!', 'error')
            return redirect('/import/cpanel')
        try:
            result = subprocess.run(['opencli', 'user-import', 'cpanel', path, plan_name], capture_output=True, text=True)
            # example: opencli user-import cpanel "/home/backups/cpmovefile_02512024.tar.gz" default_plan_nginx
            if result.returncode == 0:
                flash('Import started!', 'success')
            else:
                flash(f'Import failed: {result.stderr}', 'error')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')

        return redirect('/import/cpanel')
    else:
        return render_template('cpanel-import.html', title='Import cPanel account')
