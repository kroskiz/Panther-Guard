
	// the flow for process builder is start -> read output -> wait for exit
	import java.io.IOException; // handles exceptions
	import java.io.BufferedReader; // Read lines I guess
	import java.io.InputStreamReader; //converts raw bytes from process
	import java.util.ArrayList; //stores output lines as lists as well.
	import java.time.OffsetDateTime; // date-time check

	public class ProcessScanner {
	    public static void main (String[]args) throws IOException, InterruptedException{
	    // Start the OS detection inside main
	    // Windows
	    String detection = System.getProperty("os.name");
	    String detectionL = detection.toLowerCase();
	    boolean isWindows = detectionL.contains("win");
	    // Array of commands
	    String [] command;
	    //Confirmation
	    if(isWindows) {
	     command = new String[] {"tasklist", "/fo", "csv", "/nh"}; // temporarily print each lines
	    }
	    else {
	    command = new String[] {"ps","aux"};
	    }
	   // Create Process Builder Object	  
	    ProcessBuilder p = new ProcessBuilder(command);
	    p.redirectErrorStream(true); // Merges error output into normal output.
	   // start the processes:
	    Process process = p.start();
	    // Connect to process output, turn them into characters and read the lines
	    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
	    // ArrayList to store the lines
	    ArrayList<String> lines = new ArrayList<>();
	    String line;
	    while((line = reader.readLine()) != null) { // while there are lines keep reading
	    	lines.add(line);
	    	
	    }
	    // Get Java Time - Stamp:
	    String timeStamp = OffsetDateTime.now().toString(); // gives the current time and date.
	   
	    boolean first = true; // checks if there's a first object
	    System.out.println("["); // for JSON file
	    for(String row : lines) { // try to print chrome.exe with no quotes for every lines
	    int end = row.indexOf('"',1); //
	    String name = row.substring(1,end); // cuts text from the quotes from index 1 - 10
	    // Threat Level System
	    String threatLevel = "low"; // assign low by default
	    if(name.equals("unknown_process.exe")) {
	     threatLevel = "high";
	    }
	    if(!first)
	    System.out.println(",");
	    System.out.println("{\"status\": \"running\", \"process_name\": \"" + name + "\", \"threat_level\": \"" + threatLevel + "\", \"timestamp\": \"" + timeStamp + "\"}" );
	    first = false;
	    }
	    System.out.println("]");	    	
	    
	  }
	}


