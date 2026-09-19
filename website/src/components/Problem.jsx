import React from 'react';
import { ArrowDown, Link } from 'lucide-react';
import './Problem.css';

export default function Problem() {
  return (
    <section className="section">
      <div className="container">
        <div className="section-header">
          <h2>A link doesn't tell you the whole story.</h2>
          <p>
            A link can hide redirects, shortened URLs, tracking parameters, unfamiliar destinations, or contextual signals that aren't obvious before you click.
          </p>
        </div>

        <div className="problem-visual">
          <div className="problem-side problem-before">
            <div className="problem-label">WHAT YOU SEE</div>
            <div className="problem-card">
              <p className="problem-claim">Claim your reward &rarr;</p>
              <div className="problem-url">
                <Link size={16} />
                <span>https://bit.ly/example</span>
              </div>
            </div>
          </div>
          
          <div className="problem-arrow">
            <ArrowDown size={32} />
          </div>
          
          <div className="problem-side problem-after">
            <div className="problem-label">WHAT MAY BE BEHIND IT</div>
            <div className="problem-flow">
              <div className="flow-step">Shortened URL</div>
              <ArrowDown size={20} className="flow-arrow" />
              <div className="flow-step">Redirect</div>
              <ArrowDown size={20} className="flow-arrow" />
              <div className="flow-step">Final destination</div>
              <ArrowDown size={20} className="flow-arrow" />
              <div className="flow-step warning">Account / payment / job / offer</div>
            </div>
          </div>
        </div>
        
        <div className="problem-conclusion">
          <p><strong>BehindTheLink</strong> makes those details visible before you open the link.</p>
        </div>
      </div>
    </section>
  );
}
