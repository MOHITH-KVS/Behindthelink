import React from 'react';
import { Code2, Archive } from 'lucide-react';
import { GITHUB_URL, RELEASE_URL } from '../config';
import './OpenSource.css';

export default function OpenSource() {
  return (
    <section className="section bg-light-alt">
      <div className="container">
        <div className="os-container">
          <div className="os-content">
            <h2 className="os-title">Built in the open.</h2>
            <p className="os-desc">
              BehindTheLink is open source and distributed through GitHub Releases.
            </p>
            
            <div className="os-actions">
              <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer" className="btn btn-outline os-btn">
                <Code2 size={20} />
                View on GitHub
              </a>
              <a href={RELEASE_URL} target="_blank" rel="noopener noreferrer" className="btn btn-outline os-btn">
                <Archive size={20} />
                View Release
              </a>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
