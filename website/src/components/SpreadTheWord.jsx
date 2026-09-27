import React, { useState } from 'react';
import { MessageCircle, Link, CheckCircle2 } from 'lucide-react';
import './SpreadTheWord.css';

const LinkedinIcon = ({ size = 24 }) => (
  <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z"></path>
    <rect x="2" y="9" width="4" height="12"></rect>
    <circle cx="4" cy="4" r="2"></circle>
  </svg>
);

export default function SpreadTheWord() {
  const [copied, setCopied] = useState(false);
  const websiteUrl = "https://behindthelink.vercel.app/";
  
  const handleCopyLink = async () => {
    try {
      await navigator.clipboard.writeText(websiteUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy link', err);
    }
  };

  const whatsappText = encodeURIComponent(`Hey! I found a free Chrome extension called BehindTheLink 🔍 It helps you see what's behind a link before you click it — including its destination, redirects, tracking and other useful warning signs. Check it out 👇\n${websiteUrl}`);
  const whatsappUrl = `https://wa.me/?text=${whatsappText}`;

  // For LinkedIn, we pass the URL.
  const linkedinUrl = `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(websiteUrl)}`;

  return (
    <section className="section spread-section">
      <div className="container">
        <div className="section-header">
          <span className="section-eyebrow">SPREAD THE WORD</span>
          <h2>Help make the web a little safer 🔍</h2>
          <p>
            We all receive links every day — from job opportunities and delivery messages to account verification and random messages. 
            If BehindTheLink helps you pause before clicking an unfamiliar link, share it with someone who might find it useful.
          </p>
        </div>

        <div className="share-cards">
          {/* WhatsApp Card */}
          <div className="share-card">
            <div className="share-card-header">
              <div className="share-icon whatsapp">
                <MessageCircle size={24} />
              </div>
              <h3 className="share-card-title">Share on WhatsApp</h3>
            </div>
            <div className="share-card-body">
              <p className="share-quote">
                "Hey! I found a free Chrome extension called BehindTheLink 🔍 It helps you see what's behind a link before you click it — including its destination, redirects, tracking and other useful warning signs. Check it out 👇"
              </p>
            </div>
            <a href={whatsappUrl} target="_blank" rel="noopener noreferrer" className="btn btn-primary share-btn whatsapp-btn" aria-label="Share on WhatsApp">
              <MessageCircle size={18} />
              Share on WhatsApp
            </a>
          </div>

          {/* LinkedIn Card */}
          <div className="share-card">
            <div className="share-card-header">
              <div className="share-icon linkedin">
                <LinkedinIcon size={24} />
              </div>
              <h3 className="share-card-title">Share on LinkedIn</h3>
            </div>
            <div className="share-card-body">
              <p className="share-quote">
                "I just discovered BehindTheLink 🔍 — a free Chrome extension that helps you understand what's behind a link before clicking it. It shows the destination, redirects, tracking and other useful signals. A simple idea for safer browsing. 👇"
              </p>
            </div>
            <a href={linkedinUrl} target="_blank" rel="noopener noreferrer" className="btn btn-primary share-btn linkedin-btn" aria-label="Share on LinkedIn">
              <LinkedinIcon size={18} />
              Share on LinkedIn
            </a>
          </div>

          {/* Copy Link Card */}
          <div className="share-card">
            <div className="share-card-header">
              <div className="share-icon copylink">
                <Link size={24} />
              </div>
              <h3 className="share-card-title">Share BehindTheLink</h3>
            </div>
            <div className="share-card-body">
              <p className="share-quote">
                "Before you click a link, see what's behind it. 🔍 Try BehindTheLink — a free, privacy-conscious Chrome extension."
              </p>
            </div>
            <button onClick={handleCopyLink} className={`btn btn-primary share-btn copy-btn ${copied ? 'copied' : ''}`} aria-label="Copy website link">
              {copied ? (
                <>
                  <CheckCircle2 size={18} />
                  Link copied!
                </>
              ) : (
                <>
                  <Link size={18} />
                  Copy Link
                </>
              )}
            </button>
          </div>
        </div>

        <div className="motivational-message">
          <h3>One small pause can make a difference.</h3>
          <p>Don't click first. Look behind the link first. 🔗</p>
        </div>
      </div>
    </section>
  );
}
