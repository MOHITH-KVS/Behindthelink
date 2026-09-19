import React from 'react';
import { MousePointer2, Clock, Eye, CheckCircle2 } from 'lucide-react';
import './HowToUse.css';

export default function HowToUse() {
  const steps = [
    {
      num: "1",
      title: "Hover",
      desc: "Hover over any link.",
      icon: <MousePointer2 size={24} />
    },
    {
      num: "2",
      title: "Wait",
      desc: "Give BehindTheLink a moment to inspect it.",
      icon: <Clock size={24} />
    },
    {
      num: "3",
      title: "Read",
      desc: "Check the destination, link type, safety signals, and explanation.",
      icon: <Eye size={24} />
    },
    {
      num: "4",
      title: "Decide",
      desc: "Use the information to decide whether you want to continue.",
      icon: <CheckCircle2 size={24} />
    }
  ];

  return (
    <section className="section bg-light-alt">
      <div className="container">
        <div className="section-header">
          <h2>Using BehindTheLink is simple.</h2>
        </div>
        
        <div className="use-flow">
          {steps.map((step, idx) => (
            <React.Fragment key={idx}>
              <div className="use-step">
                <div className="use-icon-wrapper">{step.icon}</div>
                <h3 className="use-title">{step.num}. {step.title}</h3>
                <p className="use-desc">{step.desc}</p>
              </div>
              
              {idx < steps.length - 1 && (
                <div className="use-connector">
                  <div className="use-arrow">&rarr;</div>
                  <div className="use-arrow-mobile">&darr;</div>
                </div>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>
    </section>
  );
}
