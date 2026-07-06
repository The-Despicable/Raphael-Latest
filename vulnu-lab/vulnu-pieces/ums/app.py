from flask import Flask, request, jsonify
app = Flask(__name__)

students = {102: {"name": "Alice", "grade": 85}, 103: {"name": "Bob", "grade": 90}}

@app.route('/students/view')
def view_student():
    sid = request.args.get('id', 102)
    return jsonify(students.get(int(sid), students[102]))

@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    data = request.get_json() or {}
    return jsonify({"updated": data, "status": "success"})

@app.route('/api/health')
def health():
    return jsonify({"debug": True, "stack": "simulated trace", "env": "development"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)