import React from 'react';
import { MousePointer2, Search, BookOpen, UserCircle } from 'lucide-react';
import './HowItWorks.css';

export default function HowItWorks() {
  const steps = [
    {
      num: "01",
      title: "Hover",
      desc: "Move your mouse over a link.",
      icon: <MousePointer2 size={24} />
    },
    {
      num: "02",
      title: "Inspect",
      desc: "BehindTheLink checks the link and available destination information.",
      icon: <Search size={24} />
    },
    {
      num: "03",
      title: "Understand",
      desc: "See what we found in plain language.",
      icon: <BookOpen size={24} />
    },
    {
      num: "04",
      title: "Decide",
      desc: "Continue, go back, or investigate further. You decide.",
      icon: <UserCircle size={24} />
    }
  ];

  return (
    <section id="how-it-works" className="section section-dark">
      <div className="container">
        <div className="section-header">
          <h2>Hover. Inspect. Understand. Decide.</h2>
        </div>
        
        <div className="steps-container">
          {steps.map((step, idx) => (
            <div key={idx} className="step-card">
              <div className="step-icon-wrapper">
                {step.icon}
              </div>
              <div className="step-num">{step.num}</div>
              <h3 className="step-title">{step.title}</h3>
              <p className="step-desc">{step.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
