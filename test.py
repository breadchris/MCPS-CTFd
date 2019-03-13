from CTFd import create_app
from CTFd.models import Evidence, EvidenceConnection
import yaml
from flask_sqlalchemy import SQLAlchemy

app = create_app()
db = SQLAlchemy(app)

with open('evidence.yaml') as f:
    data = yaml.safe_load(f)

evidence_stuff = data['evidence']

evidence_objs = {}
conns = []
for evidence_data in evidence_stuff:
    name = evidence_data['name']
    flag = evidence_data['flag']
    conn = evidence_data['conn']
    evidence_objs[name] = Evidence(name, flag)
    if conn != '' and conn is not None:
        conns.append((name, conn))
db.session.commit()
db.session.flush()

for c in conns:
    EvidenceConnection(evidence_objs[c[0]].eid, evidence_objs[c[1]].eid)
db.session.commit()
db.session.flush()

