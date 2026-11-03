
	import java.io.IOException; // handles exceptions
	import java.io.BufferedReader; // Read lines I guess
	import java.io.InputStreamReader; //converts raw bytes from process
	import java.util.ArrayList; //stores output lines as lists as well.
	import java.time.OffsetDateTime; // date-time check
	import java.io.PrintWriter; // print the JSON Script

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
	    process.waitFor(); // pauses java program until tasklist has completely finished, don't move to exit while it is still running
	    // Get Java Time - Stamp:
	    String timeStamp = OffsetDateTime.now().toString(); // gives the current time and date.
	   
	    boolean first = true; // checks if there's a first object
	    // Print Writer for the JSON file // out.println allows the program to print the lines in a JSON file
	    PrintWriter out;
	    if (args.length > 0) {
	    out = new PrintWriter(args[0]);
	    } else {
	    out = new PrintWriter(System.out, true);
	    }
	    out.println("["); // for JSON file
	    for(String row : lines) { // try to print chrome.exe with no quotes for every lines
	    int end = row.indexOf('"',1); //
	    String name = row.substring(1,end); // cuts text from the quotes from index 1 - end
	    // Threat Level System
	    String threatLevel = "low"; // assign low by default
	    if(name.equals("unknown_process.exe")) {
	     threatLevel = "high";
	    }
	    if(!first)
	    out.println(",");
	    out.println("{\"status\": \"running\", \"process_name\": \"" + name + "\", \"threat_level\": \"" + threatLevel + "\", \"timestamp\": \"" + timeStamp + "\"}" );
	    first = false;
	    }
	    out.println("]");
	    out.close(); // Close the print Writer
	    
	  }
	}


