2021

Student: Omri Farkash
ID: 308438852
User Name: omri.farkash

USAGE:
complie file SinkholeServer.java and run it, you may add a single argument, 
path to a blocklist file which contains a single legal somain name per line,
all domains in the block list wont get resolved by this DNS server.


IMPORTANT NOTES:
*The server is listening on port 5300, can be changes in the global variables in the head of the java file
*The server doesn't implemented a timer, if the server doesn't get an reply to his query
we will continue waiting for ever, in this case you should run restart the program
*The server will print to standart output, all servers addresses in his recursive proccess to resolved the query
*The program will throw err message if something went wrong, and get shut down