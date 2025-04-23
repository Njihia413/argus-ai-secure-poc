@app.route('/api/security-metrics', methods=['GET'])
def get_security_metrics():
    try:
        # Get auth token
        auth_token = request.headers.get('Authorization')
        if not auth_token:
            return jsonify({'error': 'Authorization required'}), 401

        auth_token = auth_token.replace('Bearer ', '')

        # Verify auth session
        auth_session = AuthenticationSession.query.filter_by(session_token=auth_token).first()
        if not auth_session:
            return jsonify({'error': 'Invalid auth token'}), 401

        # Query user counts
        total_users = Users.query.count()
        users_with_keys = Users.query.filter(Users.credential_id.isnot(None)).count()
        users_without_keys = total_users - users_with_keys

        # Format data for the pie chart
        metrics_data = [
            {'name': 'With Security Key', 'value': users_with_keys},
            {'name': 'Without Security Key', 'value': users_without_keys}
        ]

        return jsonify({'metrics': metrics_data})

    except Exception as e:
        print(f"Error getting security metrics: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500