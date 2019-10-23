package caso2_mc.londono_cf.infante;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;


public class Protocolo {
	
	public static void procedimiento(BufferedReader consoleReader, PrintWriter clientWriter, BufferedReader clientReader) {
		
//		java.security.cert.X509Certificate certificado = generarCertificado(llaves);
//		byte[] certificadoEnBytes = certificado.getEncoded( );
//		String certificadoEnString = printBase64Binary(certificadoEnBytes);
//		socketParaComunicacion.println(certificadoEnString);
		
		String protocolLine;			
		
		clientWriter.println("HOLA");
		protocolLine = clientReader.readLine();
		if(protocolLine != null)
		{
			System.out.println(protocolLine);
		}
		if(!protocolLine.equals("ERROR")) 
		{

//			System.out.println("Seleccione un algoritmo de cifrado simetrico : ");
//			System.out.println("1. AES");
//			System.out.println("2. BLOWFISH");
//
//			String linea = bfConsola.readLine();
			String algoritmoSimetrico = "";

			int tamanioLlaveSecreta = 128;

			int tamanioParejaLlaves = 1024;
			
			//seleccion de algoritmo simetrico

			Random rand = new Random();
			  int randomNum = rand.nextInt((2 - 1) + 1) + 1;
			switch (randomNum) {
			case 1:
				algoritmoSimetrico = Cliente.AES;
				break;
			case 2:
				algoritmoSimetrico = Cliente.BLOWFISH;
				break;
			default:
				algoritmoSimetrico = Cliente.AES;
				break;
			}

			String algoritmoAsimetrico = Cliente.RSA;


			//seleccion de algoritmo HMAC
//			System.out.println("Seleccione un algoritmo HMAC : ");
//			System.out.println("1. HMACSHA1");
//			System.out.println("2. HMACSHA256");
//			System.out.println("3. HMACSHA384");
//			System.out.println("4. HMACSHA512");
//			linea = bfConsola.readLine();

	
			
			String algoHMAC = "";
			String algoDigest="";
			 randomNum = rand.nextInt((4 - 1) + 1) + 1;

			switch (randomNum) {
			case 1:
				algoHMAC = Cliente.HMACSHA1;
				algoDigest = Cliente.SHA1;
				break;
			case 2:
				algoHMAC = Cliente.HMACSHA256;
				algoDigest = Cliente.SHA256;

				break;
			case 3:
				algoHMAC = Cliente.HMACSHA384;
				algoDigest = Cliente.SHA384;
				break;
			case 4:
				algoHMAC = Cliente.HMACSHA512;
				algoDigest = Cliente.SHA512;
				break;
			default :
				algoHMAC = Cliente.HMACSHA512;
				algoDigest = Cliente.SHA512;
			}

			String alg = "ALGORITMOS:"+algoritmoSimetrico+":"+algoritmoAsimetrico+":"+algoHMAC;
			clientWriter.println(alg);
			if((protocolLine = clientReader.readLine()) != null)
			{
				System.out.println(protocolLine);
			}

			if(!protocolLine.equals(Cliente.ERROR))
			{
				//generar pareja de llaves asimetricas
				KeyPairGenerator kp = KeyPairGenerator.getInstance(Cliente.RSA);
				kp.initialize(tamanioParejaLlaves,new SecureRandom());
				KeyPair parejaDeLlaves = kp.generateKeyPair();
				
				//generar certificado
				java.security.cert.X509Certificate certificado = generarCertificado(parejaDeLlaves);
				byte[] certificadoEnBytes = certificado.getEncoded( );
				String certificadoEnString = Hex.toHexString(certificadoEnBytes);
				
				clientWriter.println(certificadoEnString);
				
				String certificadoServidor = "";
				if((protocolLine = clientReader.readLine()) != null)
				{
					certificadoServidor = protocolLine;
				}

				//Obtener llave publica servidor
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				byte[] certificadoServerEnBytes = DatatypeConverter.parseHexBinary(certificadoServidor);
				InputStream in = new ByteArrayInputStream(certificadoServerEnBytes);
				X509Certificate certificadoServer = (X509Certificate) cf.generateCertificate(in);	
				//obtenemos llave pub del server
				PublicKey llavePubServer = certificadoServer.getPublicKey();

				//------------------------------------------------



				//obtencion de llave secreta(simetrica)
				KeyGenerator keygen = KeyGenerator.getInstance(algoritmoSimetrico);
				keygen.init(tamanioLlaveSecreta);
				SecretKey secretK = keygen.generateKey();

				//cifrado respecto a la publica del servidor
				Cipher cifrador = Cipher.getInstance(algoritmoAsimetrico);
				byte[] llaveSecretaEnBytes = secretK.getEncoded();
				cifrador.init(1, llavePubServer);
				byte[] byteCifradoLlaveSecreta = cifrador.doFinal(llaveSecretaEnBytes);

				//termina cifrado-------------------


				//envio de llave secreta cifrada con publica del servidor
				clientWriter.println(DatatypeConverter.printHexBinary(byteCifradoLlaveSecreta));
				
				String cifradoConPublicaMia = "";
				if((protocolLine = clientReader.readLine()) != null)
				{
					cifradoConPublicaMia = protocolLine ;
				}

				//decriptamos mensaje para saber si el server nos responde con la misma llave secreta
				cifrador = Cipher.getInstance(algoritmoAsimetrico);
				//se decripta respecto a mi privada porque el servidor me responde con mi publica entonces... 
				//soy yo, el unico que podria desencriptar el mensaje
				cifrador.init(Cipher.DECRYPT_MODE, parejaDeLlaves.getPrivate());
				byte[] x = DatatypeConverter.parseHexBinary(cifradoConPublicaMia);
				byte[] llaveSecretaByte  = cifrador.doFinal(x);

				String llaveSecretaEnString = DatatypeConverter.printHexBinary(llaveSecretaEnBytes);
				//verificamos igualdad entre la llave secreta generada y la que envio el servidor
				
				boolean continuar = false;	
				if(llaveSecretaEnString.equals(DatatypeConverter.printHexBinary(llaveSecretaByte)))
				{
					System.out.println("Se realiz� adecuadamente el intercambio de llave secreta");
					clientWriter.println("OK");
					continuar = true;
				}
				else
				{
					System.out.println("No se intercambi� correctamente la llave secreta, lo sentimos.");
				}

				//Llave secreta(version del server)
				SecretKey key2 = new SecretKeySpec(llaveSecretaByte, 0, llaveSecretaByte.length, algoritmoSimetrico);


				if(continuar) 
				{
					//generamos datos
					String datos = Cliente.getDatos();
					byte[] datosEnBytes = datos.getBytes();


					//cifrado simetrico de los datos
					Cipher cifradorNuevo = Cipher.getInstance(algoritmoSimetrico+"/ECB/PKCS5Padding");
					cifradorNuevo.init(1 , key2);
					byte[] datosCifradosSim = cifradorNuevo.doFinal(datosEnBytes);

					clientWriter.println(Hex.toHexString(datosCifradosSim));
					//--------------------fin de envio de cifrado simetrico de los datos

											
					//HMAC de los datos
					Mac mac = Mac.getInstance(algoHMAC);
					mac.init(key2);
					byte[] datosHasheadosHMAC = mac.doFinal(datosEnBytes);

					String datosHasheadosHmacStr = DatatypeConverter.printHexBinary(datosHasheadosHMAC); 

					//Envio de datos en hexa del proceso hmac
					clientWriter.println(datosHasheadosHmacStr);

					//obtenemos la respuesta del server
					String respuestaFinal = "";
					if((protocolLine = clientReader.readLine()) != null)
					{
						respuestaFinal = protocolLine ;
					}
					
					if(!respuestaFinal.equals(Cliente.ERROR))
					{
						//probar que la respuesta es correcta
						//1. descriframos el mensaje con la publica del servidor
						cifrador = Cipher.getInstance(algoritmoAsimetrico);
						cifrador.init(Cipher.DECRYPT_MODE, llavePubServer);
						byte [] respuestaBytes = DatatypeConverter.parseHexBinary(respuestaFinal);
						byte[] hmacEnBytes = cifrador.doFinal(respuestaBytes);
						//2. verificacion de igualdad entre hmacs
						if(datosHasheadosHmacStr.equals(DatatypeConverter.printHexBinary(hmacEnBytes)))
						{
							System.out.println("El proceso fue realizado correctamente");
						}
					}
					else
					{
						System.out.println("ERROR : Algo fallo, lo sentimos.");
					}
				}
				else
				{
					System.err.println(Cliente.ERROR);
				}
			}
			else
			{
				System.out.println("No se enviaron con el formato correcto los algoritmos");
			}
		}
		else
		{
			System.out.println("El servidor no respondi�.");
		}
	}
	
	public static java.security.cert.X509Certificate generarCertificado(KeyPair kp) 
	{
		try
		{
			
			Provider pro = new BouncyCastleProvider();
			Security.addProvider(pro);
			//fecha inicial de expedicion
			long fechaActual = System.currentTimeMillis();
			BigInteger sn = new BigInteger(Long.toString(fechaActual));
			Date fechaDefinitiva = new Date(fechaActual);

			X500Name name = new X500Name("CN=localhost");
			
			Date fechaFinal = new Date(System.currentTimeMillis());
			//Firma
			ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());
			//Lo genero con mi publica para que el server lo pueda leer
			JcaX509v3CertificateBuilder constructorCertificador = new JcaX509v3CertificateBuilder(name, sn, fechaDefinitiva, fechaFinal, name, kp.getPublic());
			
			constructorCertificador.addExtension(new ASN1ObjectIdentifier("10.23.19"), true, new BasicConstraints(true));
			
			//certificado obtenido
			X509Certificate certificado = new JcaX509CertificateConverter().setProvider(pro).getCertificate(constructorCertificador.build(signer));


			return certificado;

		}
		catch(OperatorCreationException  | CertificateException ce)
		{
			ce.printStackTrace();
			return null;
		} catch (CertIOException e) 
		{
			e.printStackTrace();
		}
		return null;
	}
}
