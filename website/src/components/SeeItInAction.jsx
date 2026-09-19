import React from 'react';
import { Check, Info } from 'lucide-react';
import './SeeItInAction.css';

export default function SeeItInAction() {
  return (
    <section className="section bg-light-alt">
      <div className="container">
        <div className="section-header">
          <h2>Understand a link before you open it.</h2>
        </div>
        
        <div className="action-demo">
          <div className="action-webpage">
            <div className="webpage-header">Inbox (1)</div>
            <div className="webpage-body">
              <div className="email-subject">Account Security Notice</div>
              <div className="email-content">
                <p>We noticed unusual activity on your account. Please secure it immediately.</p>
                <div className="email-action-wrapper">
                  <a href="#" className="email-button hover-active">Verify your account now</a>
                  
                  {/* Hover Popup */}
                  <div className="btl-popup">
                    <div className="btl-popup-header">
                      <span>BehindTheLink</span>
                    </div>
                    <div className="btl-popup-content">
                      <div className="btl-section">
                        <div className="btl-label">DESTINATION</div>
                        <div className="btl-value">example-login.com</div>
                        <div className="btl-status positive">
                          <Check size={14} /> Redirect destination confirmed
                        </div>
                      </div>
                      
                      <div className="btl-section">
                        <div className="btl-label">SAFETY</div>
                        <div className="btl-value">— No safety verdict</div>
                      </div>
                      
                      <div className="btl-section btl-highlight">
                        <div className="btl-highlight-title">Some things to know</div>
                        <ul className="btl-list">
                          <li>Account or sign-in action</li>
                          <li>Redirecting link</li>
                        </ul>
                      </div>
                      
                      <div className="btl-section">
                        <div className="btl-label">WHY SHOULD I CARE?</div>
                        <div className="btl-text">
                          This link appears to involve an account action and redirects to another destination.
                        </div>
                      </div>
                      
                      <div className="btl-section">
                        <div className="btl-label">WHAT SHOULD I DO?</div>
                        <div className="btl-text alert">
                          Check the destination domain before signing in.
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
