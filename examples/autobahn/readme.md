Autobahn Example
================

This example has a client and server application setup for communicating
with the Autobahn Test Suite.

The run_*.sh scripts make use of the Autobahn container.

## Client

- perf tests are disabled since they seem to be IO bound
- ./run_fuzzing_server.sh to run the test server
- ./bin/client to run the client (under test)

## Server

- ./bin/server to run the server (under test)
- ./run_fuzzing_client.sh to run the test client
