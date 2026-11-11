
	import java.io.IOException; // handles exceptions
	import java.io.BufferedReader; // Read lines I guess
	import java.io.InputStreamReader; //converts raw bytes from process
	import java.util.ArrayList; //stores output lines as lists as well.
	import java.time.OffsetDateTime; // date-time check
	import java.io.PrintWriter; // print the JSON Script

	public class ProcessScanner {
	    public static void main (String[]args) {
	    // Start the OS detection inside main
	    // Windows
	    String detection = System.getProperty("os.name");
	    String detectionL = detection.toLowerCase();
	    boolean isWindows = detectionL.contains("win");
	    // Array of commands
	    String [] command;
	    //Confirmation
	    if(isWindows) {
	     command = new String[] {"tasklist", "/fo", "csv", "/nh"}; // help detect OS => Windows
	    }
	    else {
	    command = new String[] {"ps","aux"}; // note that I have not worked on the iOS and Linux parts.
	    }
	   // Create Process Builder Object	  
	    ProcessBuilder p = new ProcessBuilder(command);
	    p.redirectErrorStream(true); // Merges error output into normal output.
	    // wrap everything in a try catch statement
	 // ArrayList to store the lines
	    ArrayList<String> lines = new ArrayList<>();
	    // Try statement to catch process failures and check exit code.
	    try {
	    // start the processes:
	    Process process = p.start();
	    // Connect to process output, turn them into characters and read the lines
	    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
	  
	    String line;
	    while((line = reader.readLine()) != null) { // while there are lines keep reading
	    	lines.add(line);
	    }
	    int exitCode = process.waitFor(); // pauses java program until tasklist has completely finished, don't move to exit while it is still running
	    if(exitCode != 0) {
	    System.err.println("Scan command failed with exit code: " + exitCode);
	    System.exit(1);
	     }
	    }
	    // Catch errors statements for process
	    catch(IOException e) {
	      System.err.println("Failed to run scan command: " + e.getMessage());
	      System.exit(1);
	    }
	    catch(InterruptedException e) {
	      System.err.println("The process was interrupted " + e.getMessage());
	      System.exit(1);
	    }
	    // Get Java Time - Stamp:
	    String timeStamp = OffsetDateTime.now().toString(); // gives the current time and date.
	   
	    boolean first = true; // checks if there's a first object
	    // Print Writer for the JSON file, out.println allows the program to print the lines in a JSON file
	    PrintWriter out = null;
	 // Try / catch statements to handle opening file errors
	    try {
	    if (args.length > 0) {
	    out = new PrintWriter(args[0]);
	    } else {
	    out = new PrintWriter(System.out, true);
	    }
	    out.println("["); // for JSON file
	    for(String row : lines) { // try to print chrome.exe with no quotes for every lines
	
	   // error handling => is empty or doesn't start with "
	    if(row.isEmpty() || !row.startsWith("\"")) 
	    	continue; // skip the line.
	    int end = row.indexOf('"',1); 
	   // error handling => if line ends with -1 then skip that line.
	    if (end == -1)
	      continue; // skip that line.
	    String name = row.substring(1,end); // cuts text from the quotes from index 1 - end
	    if(name.isEmpty())
	    	continue;
	    // JSON Name formating configuration.
	    name = name.replace("\\", "\\\\");
	    name = name.replace("\"", "\\\"");

	    // Threat Level System
	    String threatLevel = "low"; // assign low by default
	    if(name.equals("chrome.exe")) {
	     threatLevel = "low";
	    }
	    else if(name.equals("unknown_process.exe")) {
	     threatLevel = "medium";
	    }
	    else if(name.equals("malware.exe")) {
	     threatLevel = "high";
	    }
	    if(!first)
	    out.println(",");
	    out.println("{\"status\": \"running\", \"process_name\": \"" + name + "\", \"threat_level\": \"" + threatLevel + "\", \"timestamp\": \"" + timeStamp + "\"}" );
	    first = false;
	    }
	    out.println("]");
	    }
	    catch(IOException e) {
	    	System.err.println("Could not open output file: " + e.getMessage());
	    	System.exit(1);
	    	
	    }
	    // Making sure out.close always run
	    finally {
	    if(out != null) { // avoid NullPointerException
	    out.close(); // Close the print Writer
	      }
	    }
	    
	  }
	}


