package il.ac.idc.cs.sinkhole;
import java.io.*;
import java.net.*;
import java.util.*;

/* Omri Farkash 308438852
 * implementation of recursive DNS server
 * optional - provide an block list in a .txt file as the first argument
 * in the block list file, there are only 1 domain name per line
 * all domains in the block list file won't get resolved.
 */

public class SinkholeServer {

	//Global Variables
	public static final int portNumber = 5300;
	public static final int rootServerPort = 53;
	public static final int BUFFER_SIZE = 1024;
	public static final int headerLen =12;
	public static final int maxIterationsNum =16;
	public static final String suffixRootServerName =".root-servers.net";

	
	
	
	
	
	public static void main(String[] args) {
		try {
			boolean blockList_Provided = false;
			Set<String> blockListSet = new HashSet<String>();
			
			//creating Set of blocklist URLs (if block list file has been provided)
			if(args.length > 0) {
				blockList_Provided = true;
				blockListSet = creatingSet(args[0]);
			}
			
			


			
			//starting listening on port portNumber
			while(true) {
				
				//generate random root server
				String rootServerName = suffixRootServerName;
				int rand = (int) (Math.random() *13);
				char c = (char)('a' + rand);
				rootServerName = c + rootServerName;
				InetAddress root_ip_add = InetAddress.getByName(rootServerName);

				
				//init buffers for read and write data
				byte[] original_data = new byte[BUFFER_SIZE];
				byte[] received_data= new byte[BUFFER_SIZE];
				byte[] send_data;
				
				//starting servers
				DatagramSocket serverSocket = new DatagramSocket(portNumber);
				DatagramPacket original_receivedPacket = new DatagramPacket(original_data, BUFFER_SIZE);
				//receive query from client
				serverSocket.receive(original_receivedPacket);
				System.out.print("Query has been received for domain: ");
				System.out.println(hostNameString(original_receivedPacket.getData(), headerLen));
				System.out.println();
				System.out.println("start recording recursive path:");
				//remember original id
				byte id0 = original_data[0], id1 = original_data[1];
				
				
				//cheking if input is in block list (if clock list file has been provided)
				
				if (blockList_Provided) {
					if (checkBlockList(original_receivedPacket, blockListSet)) {
						//sending back Rcode == 3
						original_data[0] = id0;
						original_data[1] = id1;
						original_data[2] = -127;
						original_data[3] = -125;
						serverSocket.send(original_receivedPacket);
						serverSocket.close();
						continue;
					} 
				}
				
				//get rid of unnecessarily zeros bytes
				send_data = Arrays.copyOf(original_receivedPacket.getData(), original_receivedPacket.getLength());
				//build packet for sending to root server
				DatagramPacket sendPacket = new DatagramPacket(
						send_data, original_receivedPacket.getLength(), root_ip_add, rootServerPort);
				System.out.println(root_ip_add);
				serverSocket.send(sendPacket);
				//receiving answer from root server
				DatagramPacket receivedPacket = new DatagramPacket(received_data, BUFFER_SIZE);
				serverSocket.receive(receivedPacket);
				
				
				
				//recursive process
				int countOfIterations = 0;
				while(checkRcode(received_data) && checkANCOUNT(received_data) && checkNSCOUNT(received_data) && countOfIterations <maxIterationsNum) {
					//calculating were next authority name is written
					int index = sendPacket.getLength();
					//checking if name is written with pointer
					if(received_data[index] != -64) {
						//skipping name part
						index += received_data[index];
					}
					index +=headerLen;
					String NextHostName = hostNameString(receivedPacket.getData(), index);
					//next ip address
					InetAddress nextIPAddress = InetAddress.getByName(NextHostName);
					System.out.println(nextIPAddress);
					//redirect original message to next server
					sendPacket = new DatagramPacket(send_data, send_data.length,  nextIPAddress, rootServerPort);
					serverSocket.send(sendPacket);
					
					//getting new answer
					serverSocket.receive(receivedPacket);
					countOfIterations++;
				}

				
				//get rid of unnecessarily zeros bytes
				byte[] arr;
				arr = Arrays.copyOf(receivedPacket.getData(), receivedPacket.getLength());
		
				
				//create return packet
				DatagramPacket returnPack = new DatagramPacket(
						arr, receivedPacket.getLength(), original_receivedPacket.getAddress(), original_receivedPacket.getPort());
				//set id
				arr[0] = id0; arr[1] = id1;
				
				//set flags if there was no error
				if(checkRcode(receivedPacket.getData())) {
					arr[2]=-127; arr[3] = -128;
				}
				else {
					arr[2]= -127;
					arr[3]= -125;
				}
				
				//send return packet
				serverSocket.send(returnPack);
				serverSocket.close();
				System.out.println();
				System.out.println("done, can handle another query");
				System.out.println();
			}
		}
		catch(Exception e){
			System.out.println("an error accured: " +e);
			System.exit(-1);
		}
		

	} // main
	
	
	
	
	
	//checking header bits functions
	private static boolean checkRcode(byte[] b) {
		return (b[3] & 15) == 0;
	}
	private static boolean checkANCOUNT(byte[] b) {
		return ((b[6] == 0) && (b[7] == 0));
	}
	private static boolean checkNSCOUNT(byte[] b) {
		return ((b[8] != 0)  || (b[9] != 0));
	}
	
	
	
	
	//block list handling functions
	private static Set<String> creatingSet(String path_to_blockList_file) throws FileNotFoundException{
		try {
			File blockListFile = new File(path_to_blockList_file);
			Scanner sc = new Scanner(blockListFile);
			Set<String> ans = new HashSet<String>();
			while(sc.hasNext()) {
				ans.add(sc.nextLine());
			}
			sc.close();
			return ans;
		} catch (Exception e) {
			System.err.println("cannot open suplied block list file,\n"
					+ "USAGE: optional, enter a valid path for a block list file as the first argument");
			System.exit(-1);
			return null;
		}
	}
	
	private static boolean checkBlockList(DatagramPacket packetToCheck, Set<String> blockListSet) {
		//extract host name from packetToCheck
		byte[] data = packetToCheck.getData();
		int index = headerLen;
		String hostName=hostNameString(data, index);
		return blockListSet.contains(hostName);
	}
	
	
	
	
	//write host name in the form of 'www.hostname.com' for example
	private static String hostNameString(byte[] data, int index) {
		String hostName = "";
		int i = data[index];
		while(i>0) {
			for(int j=0; j<i; j++) {
				index++;
				hostName += (char) data[index];
			}
			index++;
			i = data[index];
			if(i>0) 
				hostName += '.';
			// 0xc0 stands for, go reading from the index written in the next byte
			else if(i == -64) {
				index++;
				index = data[index];
				hostName += "." + hostNameString(data, index);
			}
		}
		return hostName;
	}
	


} //class