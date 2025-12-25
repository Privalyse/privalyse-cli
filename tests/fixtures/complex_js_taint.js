
// Complex case: Variable aliasing
function processUserData(req, res) {
    const userInput = req.body;
    const userEmail = userInput.email; // Source
    
    // Aliasing
    const dataToLog = userEmail;
    
    // Sink
    console.log("User data:", dataToLog); 
}
