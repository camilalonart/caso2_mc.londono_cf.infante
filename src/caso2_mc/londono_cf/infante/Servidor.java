package caso2_mc.londono_cf.infante;

public class Servidor {
	private static String ERROR = "ERROR";
	private static String OK = "OK";
	
	public void fail() 
	{			
		System.out.println(ERROR);
	}

	public void success() 
	{
		System.out.println(OK);
	}

	public void execute() 
	{
		Cliente client;
		try 
		{
			client = new Cliente();
			client.run();
		} catch (Exception e) 
		{
			e.printStackTrace();
		}
	}
}
