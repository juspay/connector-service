<!--
---
title: "Prism: How We Found Light in the Chaos of Payments"
description: "The story behind naming Hyperswitch's payment abstraction library after Newton's legendary discovery"
author: "Loki"
date: 2026-03-21
og:image: /images/prism-header.png
tags: ["payments", "engineering", "story"]
---
-->

In 1665, a young Isaac Newton sat in a darkened room at Cambridge, holding a glass prism. Outside his window, a thin beam of sunlight pierced through a hole in his shutter. He placed the prism in the beam. What happened next changed how humanity understood light forever.

Instead of white light emerging from the other side, a cascade of colors streamed onto the opposite wall—red, orange, yellow, green, blue, indigo, violet. A complete spectrum. The ancient Greeks believed color was a mixture of light and darkness. Newton proved something profound: **white light isn't simple. It's hidden complexity, waiting to be revealed.**

That moment—the decomposition of white light into its constituent colors—became one of the most beautiful experiments in scientific history. And it's the exact metaphor that defines **Hyperswitch Prism**.

---

## The Chaos of Payments

Every developer who has built payments faces the same darkness Newton confronted.

You start with a simple requirement: "accept payments." Then reality explodes into fragments. Stripe has its own API. Adyen has another. PayPal, Braintree, Checkout.com—each a different language, different conventions, different quirks. The payment landscape isn't white light. It's a fractured spectrum of 70+ processors, each bending the rules differently.

We at Juspay lived this chaos for years. We built integrations. We maintained them. We watched our engineers struggle with the same problems over and over: "How do I handle 3DS for this connector?" "Why does this refund work here but fail there?" "What happens when a new processor launches?"

The payment world wasn't white. It was noise.

---

## The Prism Moment

Newton didn't create the colors. The colors were always there, hiding inside the white light. His prism simply revealed them—by understanding how light bends.

**Hyperswitch Prism does the same for payments.**

We're not building another payment processor. We're building the prism. A single, unified interface that takes the chaos of 70+ payment processors and refracts them into clarity. Your code doesn't need to know about Stripe's specific headers or Adyen's particular error codes. It speaks to Prism, and Prism speaks to everyone else.

The colors were always there. Prism just reveals them.

---

## What Makes a Prism

A prism works because of a simple physical principle: **different wavelengths bend at different angles**. Red light bends least. Violet bends most. The glass doesn't choose the colors—it *separates* what's already present.

Hyperswitch Prism separates the *essential* from the *incidental*:

- **Essential**: authorization, capture, refund, void—the universal payment verbs
- **Incidental**: each processor's quirks, specific field names, unique error formats

When you integrate with Prism, you're not learning 70 APIs. You're learning one. The prism handles the bending.

---

## Why Developers Need This

Here's what Newton understood: **complexity isn't eliminated by ignoring it—it's understood by separating it.**

Every "unified payments" library makes promises. But the real test is this: Can an AI agent read your documentation and implement a new connector? Can a developer from Team A hand off to Team B without a month of knowledge transfer?

With Prism, yes.

We designed it for **AI-first integration**. When Claude or GPT reads Prism's documentation, they understand payments. Not Stripe. Not Adyen. *Payments.* The abstraction is deep enough that intelligence—human or artificial—can reason about it.

That's the prism promise: **clarity through separation.**

---

## The Light Ahead

Newton's prism experiment was simple. A hole in a shutter. A glass triangle. A wall to catch the colors. Yet it unveiled the hidden structure of light itself.

Hyperswitch Prism is similarly simple for developers:

```python
# One line changes everything
client = PaymentClient(connector='stripe')  # or 'adyen', 'paypal'...
```

The payment processor changes. Your code doesn't. That's the prism effect.

---

## Join the Spectrum

Every great developer journey begins in darkness—confused by complexity, searching for pattern. Newton's insight wasn't that colors exist. It was that white light *contains* them.

**Your payments already work.** The processors exist. The money moves. The chaos is optional.

Hyperswitch Prism is the prism. We're here to reveal what's already there—to turn the fractured payment spectrum into one coherent beam of light.

Welcome to the other side of the glass.

---

*Hyperswitch Prism is open source. Start integrating at [connector.juspay.io](https://connector.juspay.io).*
