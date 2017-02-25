import java.io.IOException;

import arces.unibo.SEPA.application.Consumer;
import arces.unibo.SEPA.application.SEPALogger;
import arces.unibo.SEPA.application.ApplicationProfile;
import arces.unibo.SEPA.application.SEPALogger.VERBOSITY;
import arces.unibo.SEPA.commons.SPARQL.ARBindingsResults;
import arces.unibo.SEPA.commons.SPARQL.Bindings;
import arces.unibo.SEPA.commons.SPARQL.BindingsResults;
import arces.unibo.SEPA.application.ApplicationProfile.Parameters;

public class RFIDConsumer extends Consumer {

	private static String tag = "RFID Consumer";
	
	public RFIDConsumer(ApplicationProfile appProfile) {
		super(appProfile,"SUBSCRIBE_RFID_READING");
	}
	
	@Override
	public void notify(ARBindingsResults notify, String spuid, Integer sequence) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void notifyAdded(BindingsResults bindingsResults, String spuid, Integer sequence) {
		String message = "";
		for (Bindings binding : bindingsResults.getBindings()) {
			for(String var :binding.getVariables()) {
				message += " " + var + "=" + binding.getBindingValue(var);	
			}
		}
		
		SEPALogger.log(VERBOSITY.INFO, tag, message);
		
	}

	@Override
	public void notifyRemoved(BindingsResults bindingsResults, String spuid, Integer sequence) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void onSubscribe(BindingsResults bindingsResults, String spuid) {
		// TODO Auto-generated method stub
		
	}
	
	public static void main(String[] args) {
		ApplicationProfile appProfile = new ApplicationProfile();
		
		if(!appProfile.load("rfidReader.sap")) return;
			
		RFIDConsumer kp = new RFIDConsumer(appProfile);
		
		Parameters pars = appProfile.getParameters();
		
		if (!kp.join()) {
			SEPALogger.log(VERBOSITY.ERROR, tag, "Cannot join the SIB "+pars.getUrl()+":"+pars.getUpdatePort());	
			return;
		}
		
		kp.subscribe(null);
		
		System.out.println("Press x to exit...");
		try {
			while(System.in.read()!='x'){}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		};
		
		if(!kp.unsubscribe()) SEPALogger.log(VERBOSITY.ERROR, tag, "Error on unsubscribe");	
		if(!kp.leave()) SEPALogger.log(VERBOSITY.ERROR, tag, "Error on leave");
		
		SEPALogger.log(VERBOSITY.ERROR, tag, "RFID Consumer stopped");;
	}

	@Override
	public void brokenSubscription() {
		// TODO Auto-generated method stub
		
	}
}
