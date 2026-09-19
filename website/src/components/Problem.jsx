import React from 'react';
import { Link2, Repeat, MousePointerClick, MessageSquare } from 'lucide-react';
import './Problem.css';

export default function Problem() {
  const hiddenAspects = [
    {
      title: "Shortened links",
      icon: <Link2 size={24} />,
      exampleVisual: (
        <div className="aspect-visual">
          <div className="aspect-code">https://bit.ly/xxxxx</div>
          <div className="aspect-arrow">&darr;</div>
          <div className="aspect-code hidden">Destination</div>
        </div>
      ),
      explanation: "Shortened links hide the destination until the link is opened or resolved."
    },
    {
      title: "Redirects",
      icon: <Repeat size={24} />,
      exampleVisual: (
        <div className="aspect-visual">
          <div className="aspect-code">Link</div>
          <div className="aspect-arrow">&darr;</div>
          <div className="aspect-code hidden">Redirect</div>
          <div className="aspect-arrow">&darr;</div>
          <div className="aspect-code hidden">Destination</div>
        </div>
      ),
      explanation: "A link may pass through one or more destinations before reaching the final page."
    },
    {
      title: "Tracking parameters",
      icon: <MousePointerClick size={24} />,
      exampleVisual: (
        <div className="aspect-visual">
          <div className="aspect-code url-wrap">
            <span>example.com/page?</span>
            <span className="hidden">utm_source=...</span>
            <span className="hidden">&fbclid=...</span>
          </div>
        </div>
      ),
      explanation: "Some links contain tracking parameters that reveal how the link was shared or measured."
    },
    {
      title: "Context & actions",
      icon: <MessageSquare size={24} />,
      exampleVisual: (
        <div className="aspect-visual align-left">
          <div className="aspect-quote">"Verify your account"</div>
          <div className="aspect-quote">"Claim your reward"</div>
          <div className="aspect-quote">"Apply for this job"</div>
        </div>
      ),
      explanation: "The surrounding text can tell you what the link appears to be asking you to do."
    }
  ];

  return (
    <section className="section">
      <div className="container">
        <div className="section-header">
          <h2>What can be hidden behind a link?</h2>
          <p>
            A link can look simple while the URL and destination contain more information than you can see at first glance.
          </p>
        </div>

        <div className="hidden-aspects-grid">
          {hiddenAspects.map((aspect, idx) => (
            <div key={idx} className="aspect-card">
              <div className="aspect-header">
                <div className="aspect-icon">{aspect.icon}</div>
                <h3 className="aspect-title">{aspect.title}</h3>
              </div>
              <div className="aspect-body">
                <div className="aspect-example-box">
                  {aspect.exampleVisual}
                </div>
                <p className="aspect-explanation">{aspect.explanation}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
