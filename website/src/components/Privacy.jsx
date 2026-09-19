import React from 'react';
import { UserX, Database, Network } from 'lucide-react';
import './Cards.css';

export default function Privacy() {
  const items = [
    {
      title: "No account",
      desc: "No signup or personal profile.",
      icon: <UserX size={24} />
    },
    {
      title: "No browsing database",
      desc: "BehindTheLink does not maintain a database of your browsing activity.",
      icon: <Database size={24} />
    },
    {
      title: "Transparent network checks",
      desc: "Some destination checks may make separate network requests to determine redirect behavior.",
      icon: <Network size={24} />
    }
  ];

  return (
    <section className="section">
      <div className="container">
        <div className="section-header">
          <h2>Local-first by design.</h2>
          <p>
            BehindTheLink v0.1.0 does not require an account and does not use a BehindTheLink backend to store your browsing activity.
          </p>
        </div>
        
        <div className="info-cards-grid">
          {items.map((item, idx) => (
            <div key={idx} className="info-card">
              <div className="info-icon">{item.icon}</div>
              <h3 className="info-title">{item.title}</h3>
              <p className="info-desc">{item.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
