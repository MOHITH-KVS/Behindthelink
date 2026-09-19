import os
from PIL import Image, ImageDraw, ImageFont

def generate_logos():
    # Make sure branding directory exists
    os.makedirs('public/branding', exist_ok=True)
    
    # 1. Generate Favicon (Symbol Only) - 512x512
    size_fav = (512, 512)
    img_fav = Image.new('RGBA', size_fav, (255, 255, 255, 0))
    draw_fav = ImageDraw.Draw(img_fav)
    
    # Draw magnifying glass (circle + handle)
    # Circle
    draw_fav.ellipse((100, 100, 350, 350), outline=(59, 130, 246, 255), width=40)
    # Handle
    draw_fav.line((300, 300, 450, 450), fill=(59, 130, 246, 255), width=50)
    
    # Draw link symbol (overlapping)
    draw_fav.ellipse((200, 250, 300, 350), outline=(255, 255, 255, 255), width=20)
    draw_fav.line((220, 330, 280, 270), fill=(255, 255, 255, 255), width=20)
    
    img_fav.save('public/favicon.png')
    
    # Generate extension icons
    os.makedirs('../assets/icons', exist_ok=True)
    img_fav.resize((16, 16), Image.Resampling.LANCZOS).save('../assets/icons/icon-16.png')
    img_fav.resize((48, 48), Image.Resampling.LANCZOS).save('../assets/icons/icon-48.png')
    img_fav.resize((128, 128), Image.Resampling.LANCZOS).save('../assets/icons/icon-128.png')
    
    # 2. Generate Full Logo (Symbol + Wordmark) - 1200x300
    size_logo = (1200, 300)
    img_logo = Image.new('RGBA', size_logo, (255, 255, 255, 0))
    draw_logo = ImageDraw.Draw(img_logo)
    
    # Paste symbol into full logo
    symbol_resized = img_fav.resize((200, 200), Image.Resampling.LANCZOS)
    img_logo.paste(symbol_resized, (50, 50), symbol_resized)
    
    # Try to load a font, or fallback to default
    try:
        # Windows standard font for professional look
        font = ImageFont.truetype("arialbd.ttf", 140)
    except IOError:
        font = ImageFont.load_default()
        
    # Draw Wordmark "BehindTheLink"
    draw_logo.text((300, 70), "BehindTheLink", fill=(30, 41, 59, 255), font=font)
    
    img_logo.save('public/branding/behindthelink-logo.png')
    print("Logos generated successfully.")

if __name__ == "__main__":
    generate_logos()
