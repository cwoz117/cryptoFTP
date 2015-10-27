import java.net.*;
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

import java.io.*;

/**
 * Thread to deal with clients who connect to Server.  Put what you want the
 * thread to do in it's run() method.
 */

public class ServerThread extends Thread
{
	private Socket sock;  //The socket it communicates with the client on.
	private Server parent;  //Reference to Server object for message passing.
	private int idnum;  //The client's id number.
	private SecretKeySpec key;
	
	/**
	 * Constructor, does the usual stuff.
	 * @param s Communication Socket.
	 * @param p Reference to parent thread.
	 * @param id ID Number.
	 */
	public ServerThread (Socket s, Server p, int id, String key)
	{
		parent = p;
		sock = s;
		idnum = id;
		this.key = CryptoUtilities.key_from_seed(key.getBytes());
	}

	/**
	 * Getter for id number.
	 * @return ID Number
	 */
	public int getID ()
	{
		return idnum;
	}

	/**
	 * Getter for the socket, this way the parent thread can
	 * access the socket and close it, causing the thread to
	 * stop blocking on IO operations and see that the server's
	 * shutdown flag is true and terminate.
	 * @return The Socket.
	 */
	public Socket getSocket ()
	{
		return sock;
	}

	/**
	 * This is what the thread does as it executes.  Listens on the socket
	 * for incoming data and then echos it to the screen.  A client can also
	 * ask to be disconnected with "exit" or to shutdown the server with "die".
	 */
	public void run ()
	{
		BufferedReader in = null;
		BufferedWriter out = null;
		String incoming = null;
		Cipher cip = null;
		Mac hmac = null;
		
		try {
			in = new BufferedReader (new InputStreamReader (sock.getInputStream()));
			out = new BufferedWriter (new OutputStreamWriter(sock.getOutputStream()));
			
			byte[] initVec = new byte[16];
			IvParameterSpec param = new IvParameterSpec(initVec);
			
			cip = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cip.init(Cipher.DECRYPT_MODE, this.key, param);
			
			hmac = Mac.getInstance("HmacSHA1");
			hmac.init(this.key);
		}
		catch (UnknownHostException e) {
			System.out.println ("Unknown host error.");
			return;
		}
		 catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}catch (IOException e) {
			System.out.println ("Could not establish communication.");
			return;
		}
		
		
		/* Try to read from the socket */
		try {
			incoming = in.readLine ();
		}
		catch (IOException e) {
			if (parent.getFlag())
			{
				System.out.println ("shutting down.");
				return;
			}
			return;
		}
		
		/* See if we've received something */
		while (incoming != null)
		{

			if (incoming.compareTo("sen") == 0){
				System.out.println("Receiving request for data transfer");
				try {
					Socket dataCon = new Socket(sock.getInetAddress(), 2001);

					/* get file name */
					DataInputStream ds = new DataInputStream(dataCon.getInputStream());
					System.out.println("connected to clients data stream");
					int dataLen = ds.readInt();
					byte[] byteName = new byte[dataLen];
					ds.readFully(byteName);

					// get digest
					dataLen = ds.readInt();
					byte[] cipherDigest = new byte[dataLen];
					ds.readFully(cipherDigest);
					byte[] plainDigest = cip.doFinal(cipherDigest);

					// get file
					dataLen = ds.readInt();
					byte[] cipherFile = new byte[dataLen];
					ds.readFully(cipherFile);
					byte[] myDigest = hmac.doFinal(cipherFile);

					if (authenticationConfirmed(myDigest, plainDigest)){
						byte[] plaintext = cip.doFinal(cipherFile);
						FileOutputStream fos = new FileOutputStream(new String(byteName));
						fos.write(plaintext);
						fos.flush();
						fos.close();
						out.write("File stored");
						out.flush();
					} else {
						out.write("The data's authentication did not match");
						out.flush();
					}
					
					dataCon.shutdownInput();
					dataCon.close();
				}catch (IllegalBlockSizeException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					System.out.println("could not connect data stream");
				} 
			} else if (incoming.compareTo("exit") == 0){
				parent.kill (this);
				try {
					in.close ();
					sock.close ();
				}
				catch (IOException e)
				{/*nothing to do*/}
				return;
			} else if (incoming.compareTo("die") == 0) {
				parent.killall ();
				return;
			} else {
				System.out.println ("Client " + idnum + ": " + incoming);
			}
			
			/**
			 *  Try to get the next line.  If an IOException occurs it is
			 * probably because another client told the server to shutdown,
			 * the server has closed this thread's socket and is signalling
			 * for the thread to shutdown using the shutdown flag.
			 */
			try {
				incoming = in.readLine ();
			}
			catch (IOException e) {
				if (parent.getFlag())
				{
					System.out.println ("shutting down.");
					return;
				}
				else
				{
					System.out.println ("IO Error.");
					return;
				}
			}
		}
	}

	private boolean authenticationConfirmed(byte[] myDigest, byte[] cipherDigest) {
		if (myDigest.length != cipherDigest.length){
			System.out.println("digests do not have the same length");
			return false;
		}
		boolean equates = false;
		for (int i = 0; i < myDigest.length; i++){
			if (myDigest[i] != cipherDigest[i]){
				System.out.println(myDigest[i] + ", " + cipherDigest[i]);
				return false;
			}
		}
		return true;
	}
}
