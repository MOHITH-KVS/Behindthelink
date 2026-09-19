import React, { useState } from 'react';
import { Menu, X } from 'lucide-react';
import { DOWNLOAD_URL, GITHUB_URL } from '../config';
import './Navbar.css';

export default function Navbar() {
  const [isOpen, setIsOpen] = useState(false);

  const toggleMenu = () => setIsOpen(!isOpen);

  return (
    <header className="navbar-container">
      <div className="container navbar">
        <div className="nav-logo">
          <img src="/branding/behindthelink-logo.png" alt="BehindTheLink" className="logo-image" />
        </div>
        
        <nav className={`nav-links ${isOpen ? 'open' : ''}`}>
          <a href="#how-it-works" onClick={() => setIsOpen(false)}>How it works</a>
          <a href="#features" onClick={() => setIsOpen(false)}>Features</a>
          <a href="#installation" onClick={() => setIsOpen(false)}>Installation</a>
          <a href="#faq" onClick={() => setIsOpen(false)}>FAQ</a>
          <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer" onClick={() => setIsOpen(false)}>GitHub</a>
        </nav>
        
        <div className="nav-actions">
          <a href={DOWNLOAD_URL} className="btn btn-primary nav-download-btn">Download for Chrome</a>
          <button className="mobile-menu-btn" onClick={toggleMenu} aria-label="Toggle menu">
            {isOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>
      </div>
    </header>
  );
}
