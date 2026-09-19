import React from 'react';
import { Target, Repeat, Link2, LayoutTemplate, MessageSquare, AlertTriangle, ShieldAlert, Sparkles } from 'lucide-react';
import './Features.css';

export default function Features() {
  const features = [
    {
      title: "Destination",
      desc: "See where the link actually leads when the destination can be observed.",
      icon: <Target size={24} />
    },
    {
      title: "Redirects",
      desc: "Identify links that pass through another destination.",
      icon: <Repeat size={24} />
    },
    {
      title: "Link type",
      desc: "Recognize shortened, tracking, redirecting, or direct links.",
      icon: <Link2 size={24} />
    },
    {
      title: "URL structure",
      desc: "Highlight characteristics such as unusual ports, encoded URLs, IP-based hosts, or unusual domain structure.",
      icon: <LayoutTemplate size={24} />
    },
    {
      title: "Context",
      desc: "Understand what the link appears to be asking you to do.",
      icon: <MessageSquare size={24} />
    },
    {
      title: "Destination mismatch",
      desc: "Compare what a link appears to claim with the verified destination when enough evidence is available.",
      icon: <AlertTriangle size={24} />
    },
    {
      title: "Deception signals",
      desc: "Identify contextual signals such as urgency, rewards, account actions, or other potentially sensitive requests.",
      icon: <ShieldAlert size={24} />
    },
    {
      title: "Human explanations",
      desc: "Turn technical observations into simple explanations.",
      icon: <Sparkles size={24} />
    }
  ];

  return (
    <section id="features" className="section">
      <div className="container">
        <div className="section-header">
          <h2>What happens behind a link?</h2>
          <p>
            BehindTheLink looks at multiple aspects of a link to give you useful context before you open it.
          </p>
        </div>
        
        <div className="features-grid">
          {features.map((feature, idx) => (
            <div key={idx} className="feature-card">
              <div className="feature-icon">{feature.icon}</div>
              <h3 className="feature-title">{feature.title}</h3>
              <p className="feature-desc">{feature.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
