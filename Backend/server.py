import pymongo
from flask import Flask
from flask import request
import json
import hashlib
from flask_cors import CORS, cross_origin
import time

#Flask Intitialisation
app = Flask(__name__)
CORS(app)

def verify(key,tknid):
    myclient = pymongo.MongoClient("[Enter Mongo Access Key Here]")
    mydb = myclient["blacklistdb"]
    mycol = mydb[tknid]
    myquery = { "Address": key }
    mydoc = mycol.find(myquery)
    print (mydoc)
    block = 0
    for x in mydoc:
        block = block + 1

    if block > 0:
        return True
    else:
        return False



#Scan for verified accounts.
def ownerverify(key,tknid):
    myclient = pymongo.MongoClient("[Enter Mongo Access Key Here]")
    mydb = myclient["verifiedacns"]
    mycol = mydb[tknid]
    myquery = { "Wallet": key }
    mydoc = mycol.find(myquery)
    block = 0
    val = "NA"
    for x in mydoc:
        block = block + 1
        val = x["Name"]

    if block > 0:
        return True,val
    else:
        return False,val



@app.route('/scan/<string:token>/<string:key>', methods=['GET'])
def scan(token,key):
    reqa = key
    tkid = token     
    ip = str(request.remote_addr)  
    

    x,y = ownerverify(reqa,tkid)
    
    
    
    if verify(reqa,tkid):
        a = {
            "status":"OK",
            "illegal_account":"True"
        }
        
    else:
        a = {
            "status":"OK",
            "illegal_account":"False"
        }
    
    
    if (x == True):
        a["Owner"] = y
    return a,200


@app.route('/status', methods=['GET'])
def statuscheck():
    epoch = float(time.time())
    a = {
        "Server":"Active",
        "Server Time":epoch,
        "IP Address":request.remote_addr,
        "Version":2.2,
        "User Agent":str(request.headers["User-Agent"])
    }
    return a



if __name__ == '__main__':
    print("Securii Blockprotect API Server V1.0")
    app.run(debug=True)
