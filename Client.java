

import java.io.*;
import java.net.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * Client program.  Connects to the server and sends text across.
 */
public class Client 
{
	private Socket sock;  		//Socket to communicate with.
	private SecretKeySpec key;
	private Mac hmac;
	
	/**
	 * Main method, starts the client.
	 * @param args args[0] needs to be a hostname, args[1] a port number.
	 */
	public static void main (String [] args)
	{
		if (args.length != 2) {
			System.out.println ("Usage: java Client hostname port#");
			System.out.println ("hostname is a string identifying your server");
			System.out.println ("port is a positive integer identifying the port to connect to the server");
			return;
		}

		try {
			Client c = new Client (args[0], Integer.parseInt(args[1]));
		}
		catch (NumberFormatException e) {
			System.out.println ("Usage: java Client hostname port#");
			System.out.println ("Second argument was not a port number");
			return;
		}
	}

	/**
	 * Constructor, in this case does everything.
	 * @param ipaddress The host name to connect to.
	 * @param port The port to connect to.
	 */
	public Client (String ipaddress, int port)
	{
		/* Allows us to get input from the keyboard. */
		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
		String userinput;
		PrintWriter out;
		BufferedReader in;
		Cipher c = null;

		/* Try to connect to the specified host on the specified port. */
		try {
			sock = new Socket (InetAddress.getByName(ipaddress), port);
		}
		catch (UnknownHostException e) {
			System.out.println ("Usage: java Client hostname port#");
			System.out.println ("First argument is not a valid hostname");
			return;
		}
		catch (IOException e) {
			System.out.println ("Could not connect to " + ipaddress + ".");
			return;
		}

		/* Status info */
		System.out.println ("Connected to " + sock.getInetAddress().getHostAddress() + " on port " + port);

		try {
			out = new PrintWriter(sock.getOutputStream());
			in = new BufferedReader (new InputStreamReader (sock.getInputStream()));
		}
		catch (IOException e) {
			System.out.println ("Could not create output stream.");
			return;
		}

		/* get shared key for random number gen. */
		System.out.println("please enter you're shared key: ");
		try {
			String key = stdIn.readLine();
			this.key = CryptoUtilities.key_from_seed(key.getBytes());
			
			c = Cipher.getInstance("AES/CBC/PKCS5Padding");
			byte[] initVec = new byte[16];
			IvParameterSpec param = new IvParameterSpec(initVec);
			c.init(Cipher.ENCRYPT_MODE, this.key, param);
			
			hmac = Mac.getInstance("HmacSHA1");
			hmac.init(this.key);
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e1) {
			System.out.println("Could not use this key");
			return;
		}
		
		/* Wait for the user to type stuff. */
		try {
			while ((userinput = stdIn.readLine()) != null) {
				if (userinput.contains("send")){
					String[] inputData = userinput.split(" ");
					if (inputData.length != 3){
						throw new Exception("The send function was wrong");
					}
					Path p = Paths.get(inputData[1]);
					byte[] file = Files.readAllBytes(p);
					
					System.out.println("setting up request to send");
					out.println("sen");
					out.flush();
					
					ServerSocket serverAccept = new ServerSocket(2001);
					Socket dataCon = serverAccept.accept();
					
					/* Send name of file */
					DataOutputStream d = new DataOutputStream(dataCon.getOutputStream());
					d.flush();
					d.writeInt(inputData[2].length());
					d.write(inputData[2].getBytes("UTF-8"));
					d.flush();
					
					
					// Send authentication digest.
					byte[] cipherfile = c.doFinal(file);
					byte[] plainDigest = hmac.doFinal(cipherfile);
					byte[] cipherDigest = c.doFinal(plainDigest);
					d.writeInt(cipherDigest.length);
					d.write(cipherDigest);
					d.flush();

					// send file
					d.writeInt(cipherfile.length);
					d.write(cipherfile);
					d.flush();
					
					String s = in.readLine();
					System.out.println(s);
					
					dataCon.shutdownInput();
					dataCon.close();
					serverAccept.close();
				} else {
					out.println(userinput);
				}
				
				/* Tricky bit.  Since Java does short circuiting of logical 
				 * expressions, we need to checkerror to be first so it is always 
				 * executes.  Check error flushes the outputstream, which we need
				 * to do every time after the user types something, otherwise, 
				 * Java will wait for the send buffer to fill up before actually 
				 * sending anything.  See PrintWriter.flush().  If checkerror
				 * has reported an error, that means the last packet was not 
				 * delivered and the server has disconnected, probably because 
				 * another client has told it to shutdown.  Then we check to see
				 * if the user has exitted or asked the server to shutdown.  In 
				 * any of these cases we close our streams and exit.
				 */
				if ((out.checkError()) || (userinput.compareTo("exit") == 0) || (userinput.compareTo("die") == 0)) {
					System.out.println ("Client exiting.");
					stdIn.close ();
					out.close ();
					sock.close();
					return;
				}
			}
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println ("Could not read from input.");
			return;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
	}
}
