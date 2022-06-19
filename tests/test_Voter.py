from os import remove, listdir
import subprocess
import random
import re
from os.path import exists, isfile, isdir

RUN_TIMES = 1
VOTE_STR = ["YAY", "NAY"]
PASSWORD_GEN = lambda l: "".join([ chr(random.randint(97, 97+26-1) - 32) if random.randint(0,1) == 1 else chr(random.randint(97, 97+26-1)) for _ in range(l) ]) 

CREDENTIALS = []
PUBKEYS = []
VOTES = []

##################################
###                            ###
###     GEN ACTION TESTING     ###  
###                            ###
##################################
'''
    Test the bulk generation of voters credentials, as well as if the corresponding file is created in the right directory
'''
def test__bulk_generation_voter_credentials__if_valid_password(number=RUN_TIMES):    
    for _ in range(number):
        password = PASSWORD_GEN(random.randint(1, 20))
        res = subprocess.run(["./app", "-a", "GEN", "-p", password], capture_output=True, text=True, cwd="../Voter")

        assert res.returncode == 0
        assert "Data stored in" in res.stdout

        filename = res.stdout.split("Data stored in ")[1].split("\n")[0]
        CREDENTIALS.append((password, filename))
        assert re.match("(../creds/)[0-9a-zA-Z-]+(.seal)", filename) is not None

        assert exists(filename)
        assert isfile(filename)


##################################
###                            ###
###     PUB ACTION TESTING     ###  
###                            ###
##################################
''''
    Test the bulk exportation of voter's public keys, as well as if the coresponding files are created in the right directory
'''
def test__bulk_export_voter_public_key__if_valid_credentials(number=RUN_TIMES):
    test__bulk_generation_voter_credentials__if_valid_password(number)
    
    for password, credential in CREDENTIALS:
        res = subprocess.run(['./app', '-a', 'PUB', '-p', password, '-c', credential], capture_output=True, text=True, cwd='../Voter')  

        assert res.returncode == 0  
        assert "Data stored in" in res.stdout

        filename = res.stdout.split("Data stored in ")[1].split("\n")[0]
        PUBKEYS.append((password, credential, filename))
        assert re.match("(../keys/)[0-9a-zA-Z-]+", filename) is not None

        assert exists(filename)
        assert isfile(filename)


'''
    Test exportation of voter's public key, when the provided sealed credentials are tampered wtth
'''
def test__export_voter_public_key__if_tampared_credentials():
    test__bulk_generation_voter_credentials__if_valid_password()
    password, credential = CREDENTIALS[0]

    with open(credential, 'rb') as fd:
        cert = b"".join(fd.readlines()) 

    tampered = cert
    while tampered == cert:
        tampered = cert[0:-1] + random.randint(0, 255).to_bytes(1, 'big')
    
    with open(credential, 'wb') as fd:
        fd.write(tampered)

    pub_keys = listdir('../keys') if exists('../keys') and isdir('../keys') else []
    res = subprocess.run(['./app', '-a', 'PUB', '-p', password, '-c', credential], capture_output=True, text=True, cwd='../Voter')  
    assert res.returncode == 0
    assert "Failed to unseal data" in res.stdout

    assert (listdir('../keys') if exists('../keys') and isdir('../keys') else []) == pub_keys


'''
    Test exportation of voter's public key, when the provided provided password is wrong
'''
def test__export_voter_public_key__if_wrong_password():
    test__bulk_generation_voter_credentials__if_valid_password()
    _, credential = CREDENTIALS[0]
    wrong_password = PASSWORD_GEN(random.randint(5, 20))

    pub_keys = listdir('../keys') if exists('../keys') and isdir('../keys') else []
    res = subprocess.run(['./app', '-a', 'PUB', '-p', wrong_password, '-c', credential], capture_output=True, text=True, cwd='../Voter')  
    assert res.returncode == 0
    assert "Failed to unseal data" in res.stdout

    assert (listdir('../keys') if exists('../keys') and isdir('../keys') else []) == pub_keys


###################################
###                             ###
###     VOTE ACTION TESTING     ###  
###                             ###
###################################
'''
    Test the bulk voting using valid votes and valid credentials and valid public key of the ballot, 
    as well as verifying if the correct files are created in the right directory 
'''
def test__bulk_cast_valid_vote__if_valid_ballot_key__and_valid_credentials(number=RUN_TIMES):
    
    test__bulk_export_voter_public_key__if_valid_credentials(number)
    for password, credentials, _ in PUBKEYS:
        vote = VOTE_STR[random.randint(0,1)]
        votes_dir_state = listdir('../votes') if exists('../votes') and isdir('../votes') else []
        res = subprocess.run(['./app', '-a', 'VOTE', '-p', password, '-c', credentials, '-v', vote], shell=False, capture_output=True, text=True, cwd='../Voter')  

        assert res.returncode == 0  
        assert "Info: Voter Enclave successfully returned." in res.stdout

        new_votes_dir_state = listdir('../votes')
        assert len([new_vote for new_vote in new_votes_dir_state if new_vote not in votes_dir_state]) == 1
        filename = res.stdout.split("Data stored in ")[1].split("\n")[0]


        VOTES.append((password, credentials, vote, filename))
        assert re.match("(../votes/)[0-9a-zA-Z-]+(.vote)", filename) is not None

        assert exists(filename)
        assert isfile(filename)


'''
    Test casting a vote, when the provided sealed credentials are tampered wtth
'''
def test__cast_valid_vote__if_tampared_credentials():
    test__bulk_export_voter_public_key__if_valid_credentials()
    password, credential = CREDENTIALS[0]
    vote = VOTE_STR[random.randint(0,1)]

    with open(credential, 'rb') as fd:
        cert = b"".join(fd.readlines()) 

    tampered = cert
    while tampered == cert:
        tampered = cert[0:-1] + random.randint(0, 255).to_bytes(1, 'big')
    
    with open(credential, 'wb') as fd:
        fd.write(tampered)

    vote_dir_state = listdir('../votes') if exists('../votes') and isdir('../votes') else []
    res = subprocess.run(['./app', '-a', 'VOTE', '-p', password, '-c', credential, '-v', vote], capture_output=True, text=True, cwd='../Voter')  
    assert res.returncode == 0
    assert "Failed to unseal data" in res.stdout
    assert (listdir('../votes') if exists('../votes') and isdir('../votes') else []) == vote_dir_state


'''
    Test casting a vote, when the provided provided password is wrong
'''
def test__cast_valid_vote__if_wrong_password():
    test__bulk_export_voter_public_key__if_valid_credentials()
    _, credential = CREDENTIALS[0]
    vote = VOTE_STR[random.randint(0,1)]
    wrong_password = PASSWORD_GEN(random.randint(5, 20))

    vote_dir_state = listdir('../votes') if exists('../votes') and isdir('../votes') else []
    res = subprocess.run(['./app', '-a', 'VOTE', '-p', wrong_password, '-c', credential, '-v', vote], capture_output=True, text=True, cwd='../Voter')  
    assert res.returncode == 0
    assert "Failed to unseal data" in res.stdout

    assert (listdir('../votes') if exists('../votes') and isdir('../votes') else []) == vote_dir_state


### UTILS FUNCTION
'''
    Teardown function to run after each test, removes the files from the filesystem that were created during the test session
'''
def teardown_function():
    while CREDENTIALS:
        _, c = CREDENTIALS.pop()
        if exists(c) and isfile(c):
            remove(c)
            
    while PUBKEYS:
        _, _, pk = PUBKEYS.pop()
        if exists(pk) and isfile(pk):
            remove(pk)

    while VOTES:
        _, _, _, v = VOTES.pop()
        if exists(v) and isfile(v):
            remove(v)

if __name__ == '__main__':
    test__bulk_cast_valid_vote__if_valid_ballot_key__and_valid_credentials(100)
