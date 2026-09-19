import React from 'react';
import { ShieldAlert, AlertCircle, HelpCircle } from 'lucide-react';
import './Cards.css';

export default function Limitations() {
  const items = [
    {
      title: "A clean result is not a safety guarantee.",
      desc: "Not finding obvious warning signs does not prove that a website is safe.",
      icon: <ShieldAlert size={24} />
    },
    {
      title: "Local analysis has limits.",
      desc: "URL and context signals cannot identify every malicious or newly created website.",
      icon: <AlertCircle size={24} />
    },
    {
      title: "We show uncertainty.",
      desc: "If a destination cannot be verified, BehindTheLink tells you instead of pretending it knows.",
      icon: <HelpCircle size={24} />
    }
  ];

  return (
    <section className="section bg-light-alt">
      <div className="container">
        <div className="section-header">
          <h2>Built to inform, not to overpromise.</h2>
        </div>
        
        <div className="info-cards-grid">
          {items.map((item, idx) => (
            <div key={idx} className="info-card limitation-card">
              <div className="info-icon limitation-icon">{item.icon}</div>
              <h3 className="info-title">{item.title}</h3>
              <p className="info-desc">{item.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
