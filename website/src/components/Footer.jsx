import React from 'react';
import { Download, Code2 } from 'lucide-react';
import { DOWNLOAD_URL, GITHUB_URL } from '../config';
import './Footer.css';

export default function Footer() {
  return (
    <>
      {/* Final CTA */}
      <section className="section section-dark text-center final-cta">
        <div className="container">
          <h2 className="cta-title">
            Before you click.<br />
            Know what's behind it.
          </h2>
          <p className="cta-subtitle">Free. Local-first. Open source.</p>
          
          <div className="cta-actions">
            <a href={DOWNLOAD_URL} className="btn btn-primary btn-large">
              <Download size={20} />
              Download for Chrome
            </a>
            <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer" className="btn btn-outline-light btn-large">
              <Code2 size={20} />
              View on GitHub
            </a>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="footer">
        <div className="container">
          <div className="footer-top">
            <div className="footer-brand">
              <span className="footer-logo">BehindTheLink</span>
              <p className="footer-tagline">See what's behind the link before you click.</p>
            </div>
            
            <div className="footer-nav">
              <a href="#how-it-works">How it works</a>
              <a href="#features">Features</a>
              <a href="#installation">Installation</a>
              <a href="#faq">FAQ</a>
              <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer">GitHub</a>
            </div>
          </div>
          
          <div className="footer-bottom">
            <div className="copyright">&copy; 2026 BehindTheLink</div>
            <div className="footer-meta">Open source &middot; Free to use</div>
          </div>
        </div>
      </footer>
    </>
  );
}
