import React from 'react';
import { Download, Code2 } from 'lucide-react';
import { DOWNLOAD_URL, GITHUB_URL } from '../config';
import './Hero.css';

export default function Hero() {
  return (
    <section className="hero-section section-dark">
      <div className="container hero-container">
        <div className="hero-content">
          <h1 className="hero-title">See what's behind the link before you click.</h1>
          <p className="hero-subtitle">
            Hover over a link and see where it leads, how it gets there, and whether there are characteristics worth paying attention to.
          </p>
          
          <div className="hero-actions">
            <a href={DOWNLOAD_URL} className="btn btn-primary btn-large">
              <Download size={20} />
              Download for Chrome — Free
            </a>
            <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer" className="btn btn-outline-light btn-large">
              <Code2 size={20} />
              View on GitHub
            </a>
          </div>
          
          <p className="hero-disclaimer">
            No account &middot; No signup &middot; No Chrome Web Store required
          </p>
          
          <div className="hero-features">
            <div className="hero-feature">
              <div className="hero-feature-dot"></div>
              <span>Local-first</span>
            </div>
            <div className="hero-feature">
              <div className="hero-feature-dot"></div>
              <span>No account</span>
            </div>
            <div className="hero-feature">
              <div className="hero-feature-dot"></div>
              <span>Simple to use</span>
            </div>
          </div>
        </div>
        
        <div className="hero-visual">
          <div className="browser-mockup">
            <div className="browser-header">
              <div className="browser-dots">
                <span className="dot red"></span>
                <span className="dot yellow"></span>
                <span className="dot green"></span>
              </div>
              <div className="browser-url-bar">example.com</div>
            </div>
            <div className="browser-body">
              <p className="mockup-text">You have 1 new secure message.</p>
              <span className="mockup-link">View message now &rarr;</span>
            </div>
          </div>
          
          <div className="popup-mockup-wrapper">
             <div className="popup-mockup">
                <div className="popup-header">
                  <img src="/branding/behindthelink-logo.png" alt="" aria-hidden="true" className="popup-logo" />
                  <span className="popup-title">BehindTheLink</span>
                </div>
                <div className="popup-body">
                  <div className="popup-section">
                    <span className="popup-label">DESTINATION</span>
                    <span className="popup-value">login-update-auth.com</span>
                  </div>
                  <div className="popup-section">
                    <span className="popup-label warning">PAY ATTENTION</span>
                    <ul className="popup-list">
                      <li>Redirects 2 times</li>
                      <li>Requests account sign-in</li>
                    </ul>
                  </div>
                </div>
              </div>
          </div>
        </div>
      </div>
    </section>
  );
}
