package caso2_mc.londono_cf.infante;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Random;

public class Cliente extends Thread{
	public static final int PUERTO = 8000;

	private static String AES = "AES";
	private static String BLOWFISH ="BLOWFISH";
	private static String RSA = "RSA"; 
	private static String HMACSHA1 = "HMACSHA1"; 
	private static String HMACSHA256 = "HMACSHA256";
	private static String HMACSHA384 = "HMACSHA384";
	private static String HMACSHA512 = "HMACSHA512";
			
	private static String ERROR = "ERROR";
	private static String OK = "OK";


	
	public static String getCedula()
	{
		Random rand = new Random();
		return "" + rand.nextInt((5 - 1) + 1) + 1;
	}

	public static void main(String[] args) {
		Random rand = new Random();
		System.out.println(rand.nextInt((5 - 1) + 10000) * 4);
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
			Socket socket = new Socket("157.253.227.92", PUERTO);
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
