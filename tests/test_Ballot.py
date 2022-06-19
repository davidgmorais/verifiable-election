import random
import subprocess
from os import rename, remove
from os.path import exists, isfile
from turtle import st
from xml.sax.saxutils import prepare_input_source

from test_Voter import test__bulk_cast_valid_vote__if_valid_ballot_key__and_valid_credentials as generate_votes
from test_Voter import teardown_function as test_voter_teardown_function
from test_Voter import VOTES


BALLOT_CRED, BALLOT_CRED_BACKUP = "../Ballot/ballot.seal", "../Ballot/ballot_testBackup.seal"
BALLOT_PKEY, BALLOT_PKEY_BACKUP = "../Ballot/ballot", "../Ballot/ballot_testBackup"
GEN_TOTAL = 10
RUN_TIMES = 20

##################################
###                            ###
###     GEN ACTION TESTING     ###  
###                            ###
##################################
'''
    Test the generation of the ballots credentials, as well as if the corresponding file is created in the right directory
'''
def test__generation_ballot_credentials():    
    res = subprocess.run(["./app", "-a", "GEN"], capture_output=True, text=True, cwd="../Ballot")
    assert res.returncode == 0
    assert res.stdout == "Info: Ballot Enclave successfully returned.\n"

    assert exists(BALLOT_CRED)
    assert isfile(BALLOT_CRED)


def test__generation_ballot_credentials__always_creates_different():
    
    test__generation_ballot_credentials()
    with open(BALLOT_CRED, 'rb') as cred_file:
        cred_state = b"".join(cred_file.readlines())
        
    test__generation_ballot_credentials()
    with open(BALLOT_CRED, 'rb') as cred_file:
        new_cred_state = b"".join(cred_file.readlines())
    
    assert cred_state != new_cred_state


##################################
###                            ###
###     PUB ACTION TESTING     ###  
###                            ###
##################################
''''
    Test the exportation of ballot's public keys, as well as if the coresponding files are created in the right directory
'''
def test__export_ballot_public_key__if_valid_credentials():
    test__generation_ballot_credentials()
    
    res = subprocess.run(['./app', '-a', 'PUB'], capture_output=True, text=True, cwd='../Ballot')  

    assert res.returncode == 0  
    assert res.stdout == "Info: Ballot Enclave successfully returned.\n"

    assert exists(BALLOT_PKEY)
    assert isfile(BALLOT_PKEY)


'''
    Test exportation of voter's public key, when the provided sealed credentials are tampered wtth
'''
def test__export_voter_public_key__if_tampared_credentials():
    test__generation_ballot_credentials()

    with open(BALLOT_CRED, 'rb') as fd:
        cert = b"".join(fd.readlines()) 

    tampered = cert
    while tampered == cert:
        tampered = cert[0:-1] + random.randint(0, 255).to_bytes(1, 'big')
    
    with open(BALLOT_CRED, 'wb') as fd:
        fd.write(tampered)

    ballot_state = exists(BALLOT_PKEY)
    res = subprocess.run(['./app', '-a', 'PUB'], capture_output=True, text=True, cwd='../Ballot')  
    assert res.returncode == 0
    assert "Failed to unseal data\n" in res.stdout
    assert exists(BALLOT_PKEY) == ballot_state


##################################
###                            ###
###     RUN ACTION TESTING     ###  
###                            ###
##################################
'''
    Test the election process if all votes provided are valid and all voters are authorized
    The ouput should be correct and include all votes casted and the correct count but the display  order should be different
''' 
def test__run_election__if_all_voters_authorized__and_all_votes_valid(total=GEN_TOTAL, run=RUN_TIMES):
    # generate credentials and public key
    test__export_ballot_public_key__if_valid_credentials()
    
    # generate (authorized) voters and (valid) votes
    generate_votes(total)

    voting_results = None
    for _ in range(run):
        res = subprocess.run(['./app', '-a', 'RUN'], capture_output=True, text=True, cwd='../Ballot', encoding='ISO-8859-15')  
        
        assert res.returncode == 0
        assert "VOTING RESULTS" in res.stdout 

        collected_votes = int(res.stdout.split("COLLECTED VOTES:")[1].split("\n")[0].strip())
        auth_voters = int(res.stdout.split("AUTHORIZED VOTERS:")[1].split("\n")[0].strip())
        valid_votes = int(res.stdout.split("VALID VOTES:")[1].split("\n")[0].strip())
        assert collected_votes == total
        assert auth_voters == total
        assert valid_votes == total

        new_voting_results = res.stdout.split("--VOTING RESULTS--\n")[1].split("\n\n")[0].split("\n")
        assert sorted(new_voting_results) == sorted([c[2] for c in VOTES])

        if voting_results is not None:
            assert sorted(new_voting_results) == sorted(voting_results)
            # probablistically this assert will fail eventually
            # there are only n ways of order an array with size M, specially with only 2 type of votes ('YAY'/'NAY')
            assert new_voting_results != voting_results

        voting_results = new_voting_results




if __name__ == '__main__':
    test__run_election__if_all_voters_authorized__and_all_votes_valid(100, 20)
