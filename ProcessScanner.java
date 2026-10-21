
	// the flow for process builder is start -> read output -> wait for exit
	import java.io.IOException; // handles exceptions
	import java.io.BufferedReader; // Read lines I guess
	import java.io.InputStreamReader; //converts raw bytes from process
	import java.util.List; //stores output in a list
	import java.util.ArrayList; //stores output lines as lists as well.

	public class ProcessScanner {
	    public static void main (String[]args) throws IOException, InterruptedException{
	    // Start the OS detection inside main
	    // Windows
	    String detection = System.getProperty("os.name");
	    String detectionL = detection.toLowerCase();
	    System.out.println("Detected OS: " + detection);
	    boolean isWindows = detectionL.contains("win");
	    // Array of commands
	    String [] command;
	    //Confirmation
	    if(isWindows) {
	     command = new String[] {"tasklist"}; 
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
	    	System.out.println(line); // print each line
	    }
	    int exitCode = process.waitFor(); // Wait for the process to reach 0 and exit the code
	    System.out.println("Exit Code: " + exitCode);
	  }
	}


