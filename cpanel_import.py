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

# 
@app.route('/import/cpanel', methods=['GET', 'POST'])
@login_required_route
def import_cpanel_whm_account():
    if request.method == 'POST':
        return redirect('/import/cpanel')
    else:
        return render_template('cpanel-import.html', title='Import cPanel account')

