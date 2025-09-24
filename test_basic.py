"""
Test basique pour identifier le problème
"""
from flask import Flask, request, jsonify, session

app = Flask(__name__)
app.config['SECRET_KEY'] = 'test-key'

@app.route('/api/login', methods=['POST'])
def login():
    """Test de connexion basique"""
    try:
        print("=== DEBUT TEST LOGIN ===")
        
        # Test 1: Récupération des données
        data = request.get_json()
        print(f"1. Données reçues: {data}")
        
        if not data:
            print("ERREUR: Aucune donnée JSON")
            return jsonify({'error': 'Aucune donnée'}), 400
        
        # Test 2: Extraction des champs
        username = data.get('username')
        password = data.get('master_password')
        print(f"2. Username: {username}, Password: {'***' if password else None}")
        
        if not username or not password:
            print("ERREUR: Champs manquants")
            return jsonify({'error': 'Champs manquants'}), 400
        
        # Test 3: Validation basique
        if len(username) < 3:
            print("ERREUR: Username trop court")
            return jsonify({'error': 'Username trop court'}), 400
            
        if len(password) < 8:
            print("ERREUR: Password trop court")
            return jsonify({'error': 'Password trop court'}), 400
        
        # Test 4: Simulation d'authentification
        print("3. Tests de validation OK")
        
        # Test 5: Création de session
        session['user_id'] = 1
        session['username'] = username
        print("4. Session créée")
        
        print("=== SUCCES ===")
        return jsonify({
            'message': 'Test réussi',
            'username': username
        }), 200
        
    except Exception as e:
        print(f"ERREUR EXCEPTION: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Exception: {str(e)}'}), 500

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>Test</title></head>
    <body>
        <h1>Test de connexion</h1>
        <form id="loginForm">
            <input type="text" id="username" placeholder="Username" value="testuser"><br><br>
            <input type="password" id="password" placeholder="Password" value="testpassword123"><br><br>
            <button type="submit">Test Login</button>
        </form>
        <div id="result"></div>
        
        <script>
        document.getElementById('loginForm').onsubmit = function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: username,
                    master_password: password
                })
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('result').innerHTML = 
                    '<h3>Résultat:</h3><pre>' + JSON.stringify(data, null, 2) + '</pre>';
            })
            .catch(error => {
                document.getElementById('result').innerHTML = 
                    '<h3>Erreur:</h3><pre>' + error + '</pre>';
            });
        };
        </script>
    </body>
    </html>
    '''

if __name__ == '__main__':
    print("Démarrage du serveur de test...")
    app.run(debug=True, host='127.0.0.1', port=5001)  # Port différent