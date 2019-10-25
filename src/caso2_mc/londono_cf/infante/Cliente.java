package caso2_mc.londono_cf.infante;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.Charset;
import java.util.Random;

public class Cliente extends Thread{
	
	public static final int PUERTO = 8000;

	// Authentication codes for algorithms
	public static final String AES = "AES";
	public static final String BLOWFISH ="BLOWFISH";
	public static final String RSA = "RSA"; 
	public static final String HMACSHA1 = "HMACSHA1"; 
	public static final String HMACSHA256 = "HMACSHA256";
	public static final String HMACSHA384 = "HMACSHA384";
	public static final String HMACSHA512 = "HMACSHA512";
	
	public static final String ERROR = "ERROR";
	public static final String OK = "OK";
	

	public static void main(String[] args) {
		Cliente c = new Cliente();
		c.start();
	}
	
	public static String getClave() 
    { 
		Random rand = new Random();
		int n = rand.nextInt((5 - 1) + 10) * 4;
  
        // chose a Character random from this String 
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                    + "0123456789"
                                    + "abcdefghijklmnopqrstuvxyz"; 
  
        // create StringBuffer size of AlphaNumericString 
        StringBuilder sb = new StringBuilder(n); 
  
        for (int i = 0; i < n; i++) { 
  
            // generate a random number between 
            // 0 to AlphaNumericString variable length 
            int index 
                = (int)(AlphaNumericString.length() 
                        * Math.random()); 
  
            // add Character one by one in end of sb 
            sb.append(AlphaNumericString 
                          .charAt(index)); 
        } 
  
        return sb.toString(); 
    } 
	
	public static String getCedula() 
    { 
		int n = 12;
  
        // chose a Character random from this String 
        String AlphaNumericString = "0123456789";  
        // create StringBuffer size of AlphaNumericString 
        StringBuilder sb = new StringBuilder(n); 
        
        for (int i = 0; i < n; i++) { 
  
            // generate a random number between 
            // 0 to AlphaNumericString variable length 
            int index 
                = (int)(AlphaNumericString.length() 
                        * Math.random()); 
  
            // add Character one by one in end of sb 
            sb.append(AlphaNumericString 
                          .charAt(index)); 
        } 
  
        return sb.toString(); 
    } 
	
	@Override
	public void run() 
	{
		try 
		{
			iniciar();
		} catch (Exception e) 
		{
			System.err.println(e.getMessage());
		}
	}
	
	public void iniciar() {
		try {

//			Socket socket = new Socket("157.253.227.92", PUERTO);
			Socket socket = new Socket("localhost", PUERTO);
			PrintWriter pw = new PrintWriter(socket.getOutputStream(), true);
			BufferedReader bf = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			BufferedReader lectorC = new BufferedReader(new InputStreamReader(System.in));
			Protocolo.procedimiento(lectorC, pw, bf);
			lectorC.close();
			bf.close();
			pw.close();
			socket.close();
		}
		catch(Exception e){
			e.printStackTrace();
		}
		
	}
	
}
