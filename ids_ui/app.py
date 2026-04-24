from flask import Flask, render_template
import json

app = Flask(__name__)

def load_alerts():
    with open("/home/sanc/cep-proj/ids_ui/alerts.json") as f:
        return json.load(f)

@app.route("/")
def dashboard():
    alerts = load_alerts()

    status = "SAFE"
    for alert in alerts:
        if alert["severity"] == "HIGH":
            status = "UNDER ATTACK"
            break

    return render_template("index.html", alerts=alerts, status=status)

if __name__ == "__main__":
    app.run(debug=True)
