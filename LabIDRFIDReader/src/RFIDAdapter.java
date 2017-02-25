import java.io.IOException;
import java.util.HashMap;

import arces.unibo.SEPA.application.SEPALogger;
import arces.unibo.SEPA.application.Producer;
import arces.unibo.SEPA.commons.SPARQL.Bindings;
import arces.unibo.SEPA.commons.SPARQL.RDFTermLiteral;
import arces.unibo.SEPA.commons.SPARQL.RDFTermURI;
import arces.unibo.SEPA.application.ApplicationProfile;
import arces.unibo.SEPA.application.SEPALogger.VERBOSITY;
import jssc.SerialPortList;

import labid.comm.ByteUtils;
import labid.comm.SerialStream;
import labid.iso15693.ISO15693Reader;
import labid.reader.RFReaderException;

public class RFIDAdapter extends Producer {
	private String comPort;
	private SerialStream stream;
	private boolean running = true;
	
	private static ISO15693Reader reader;
	private InventoryThread thread = new InventoryThread();
	
	Bindings bindings = new Bindings();
	
	public RFIDAdapter(ApplicationProfile appProfile,String port) {
		super(appProfile,"UPDATE_RFID_READING");
		comPort = port;
	}
	
	public boolean start() {
		SerialStream stream = new SerialStream();
		try {
			stream.Open(comPort, 115200);
		} catch (IOException e) {
			return false;
		}
		reader = new ISO15693Reader(stream);
		
		try 
		{
			bindings.addBinding("resource", new RDFTermURI("iot:LABID_READER_"+ ByteUtils.toHexString(reader.getReaderUID(),'_')));
		} catch (RFReaderException e) {
			e.printStackTrace();
			System.out.println("Failed to retrieve reader UID");
			return false;
		}
			
		if (join()) System.out.println("LABID Reader URI: "+bindings.getBindingValue("resource") + " joined");
		else return false;
		
		thread.start();
		return true;
	}
	
	public boolean stop() {
		try {
			running = false;
			try {
				thread.join();
			} catch (InterruptedException e) {
				e.printStackTrace();
				return false;
			}
			if (stream != null) stream.Close();
			leave();
		} catch (IOException e) {
			return false;
		}
		return true;
	}
	
	class InventoryThread extends Thread {
		public void run() {
			HashMap<String,String> current = new HashMap<String,String>();
			HashMap<String,String> previous = null;
			byte[][] uid = null;
			String idList = "";
			boolean notify = true;
			
			while(running) {
				idList = "NULL";
				notify = true;
				uid = null;
				
				try {
					Thread.sleep(250);
					uid = reader.inventory();
				} catch (RFReaderException | InterruptedException e) {
					return;
				}
				
				//Compose new UID list
				current.clear();
				if (uid != null) {
					for (int i=0; i<uid.length; i++) {
						String uidStr = ByteUtils.toHexString(ByteUtils.revertedCopy(uid[i]), ':');
						if (i!=0) idList = idList + "|" + uidStr;
						else idList = uidStr;
						current.put(uidStr,uidStr);
					}
				}
				
				//Compare with previous list
				if (previous != null) {
					if (previous.keySet().size() == current.keySet().size()) {
						notify = false;
						for (String key : previous.keySet()) {
							if (!current.keySet().contains(key)) {
								notify = true;
								break;
							}
						}
					}
				}
				else previous = new HashMap<String,String>();
			
				//Copy previous results
				previous.clear();
				for (String key : current.keySet()) previous.put(key, key);
			
				if (notify) {
					bindings.addBinding("value", new RDFTermLiteral(idList));
					update(bindings);
					SEPALogger.log(VERBOSITY.DEBUG, "RFID Adapter", "TAGS: "+idList);
				}
				
			}
		}	
	}
		
	public static void main(String[] args) {
		ApplicationProfile appProfile = new ApplicationProfile();
		try {
			if(!appProfile.load("ApplicationProfile.xml")) return;
			
		    String[] portNames = SerialPortList.getPortNames();
		    if (portNames.length == 0) {
		    	 System.out.println("No serial ports found...exit");
		    	return;
		    }
		    System.out.println("Choose one of the following serial ports:");
		    for(int i = 0; i < portNames.length; i++){
		        System.out.printf("%d - %s\n",i,portNames[i]);
		    }
		    int sel = System.in.read();
		    System.out.printf("Selected port: %s\n",portNames[sel-48]);
		    
		    RFIDAdapter adapter = new RFIDAdapter(appProfile,portNames[sel-48]);
		    if(adapter.start()) System.out.println("RFID adapter is running...");
		    
		    System.out.println("Press X to exit");
		    while(System.in.read()!='x') {
		    	try {
		    		Thread.sleep(100);
		    	} catch (InterruptedException e) {
		    		// TODO Auto-generated catch block
		    		e.printStackTrace();
		    	}
		    }
		    if (adapter.stop()) System.out.println("RFID adapter stopped");
		    
		}
		catch(RFReaderException e) {
			System.out.println(e.getMessage());	
		}
		catch(IOException e) {
			System.out.println(e.getMessage());		
		}
	}
	
}
