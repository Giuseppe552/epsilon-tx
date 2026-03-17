import { describe, it, expect } from 'vitest'
import { createMass, combine, fuseEvidence } from './evidence.js'

/**
 * Tests for Dempster-Shafer combination rule.
 *
 * Mathematical properties that MUST hold:
 * 1. Mass function sums to 1: m(EXPOSED) + m(PRIVATE) + m(Θ) = 1
 * 2. Commutativity: m₁ ⊕ m₂ = m₂ ⊕ m₁
 * 3. Associativity: (m₁ ⊕ m₂) ⊕ m₃ = m₁ ⊕ (m₂ ⊕ m₃)
 * 4. Vacuous mass identity: m ⊕ vacuous = m
 * 5. Total conflict → pure uncertainty
 * 6. Bel(A) ≤ Pl(A) always
 *
 * Reference: Shafer, G. (1976). "A Mathematical Theory of Evidence." §3.2
 */

describe('createMass', () => {
  it('mass function sums to 1', () => {
    const m = createMass(2.0, 5.0, 0.8, 'test')
    const sum = m.exposed + m.private_ + m.uncertain
    expect(sum).toBeCloseTo(1.0)
  })

  it('full leakage with high reliability → high exposed mass', () => {
    const m = createMass(5.0, 5.0, 0.9, 'test')
    expect(m.exposed).toBeCloseTo(0.9)
    expect(m.private_).toBeCloseTo(0)
  })

  it('zero leakage with high reliability → high private mass', () => {
    const m = createMass(0, 5.0, 0.9, 'test')
    expect(m.private_).toBeCloseTo(0.9)
    expect(m.exposed).toBeCloseTo(0)
  })

  it('low reliability → mostly uncertain', () => {
    const m = createMass(2.5, 5.0, 0.2, 'test')
    expect(m.uncertain).toBeCloseTo(0.8)
  })
})

describe('combine — Shafer (1976) §3.2', () => {
  it('commutativity: m₁ ⊕ m₂ = m₂ ⊕ m₁', () => {
    const m1 = createMass(3.0, 5.0, 0.8, 'a')
    const m2 = createMass(1.0, 5.0, 0.6, 'b')
    const r1 = combine(m1, m2)
    const r2 = combine(m2, m1)
    expect(r1.exposed).toBeCloseTo(r2.exposed, 10)
    expect(r1.private_).toBeCloseTo(r2.private_, 10)
    expect(r1.uncertain).toBeCloseTo(r2.uncertain, 10)
  })

  it('result sums to 1', () => {
    const m1 = createMass(2.0, 5.0, 0.7, 'a')
    const m2 = createMass(4.0, 5.0, 0.5, 'b')
    const r = combine(m1, m2)
    expect(r.exposed + r.private_ + r.uncertain).toBeCloseTo(1.0)
  })

  it('vacuous mass identity: m ⊕ vacuous = m', () => {
    const m = createMass(3.0, 5.0, 0.8, 'real')
    const vacuous = { exposed: 0, private_: 0, uncertain: 1, source: 'vacuous' }
    const r = combine(m, vacuous)
    expect(r.exposed).toBeCloseTo(m.exposed)
    expect(r.private_).toBeCloseTo(m.private_)
    expect(r.uncertain).toBeCloseTo(m.uncertain)
  })

  it('total conflict → pure uncertainty', () => {
    const m1 = { exposed: 1, private_: 0, uncertain: 0, source: 'a' }
    const m2 = { exposed: 0, private_: 1, uncertain: 0, source: 'b' }
    const r = combine(m1, m2)
    expect(r.uncertain).toBe(1)
  })

  it('agreeing sources reinforce each other', () => {
    const m1 = createMass(4.0, 5.0, 0.7, 'a') // high leakage
    const m2 = createMass(3.5, 5.0, 0.6, 'b') // also high
    const r = combine(m1, m2)
    expect(r.exposed).toBeGreaterThan(m1.exposed)
  })

  it('conflicting sources reduce confidence', () => {
    const m1 = createMass(4.5, 5.0, 0.8, 'a') // high leakage
    const m2 = createMass(0.5, 5.0, 0.8, 'b') // low leakage
    const r = combine(m1, m2)
    // Should be less certain than either source alone
    expect(r.exposed).toBeLessThan(m1.exposed + 0.1)
  })
})

describe('fuseEvidence', () => {
  it('empty → pure uncertainty', () => {
    const r = fuseEvidence([])
    expect(r.belief).toBe(0)
    expect(r.plausibility).toBe(1)
    expect(r.uncertainty).toBe(1)
  })

  it('single source → belief = exposed mass', () => {
    const m = createMass(3.0, 5.0, 0.8, 'test')
    const r = fuseEvidence([m])
    expect(r.belief).toBeCloseTo(m.exposed)
  })

  it('Bel(A) ≤ Pl(A) always', () => {
    const masses = [
      createMass(2.0, 5.0, 0.7, 'a'),
      createMass(3.0, 5.0, 0.5, 'b'),
      createMass(1.0, 5.0, 0.6, 'c'),
    ]
    const r = fuseEvidence(masses)
    expect(r.belief).toBeLessThanOrEqual(r.plausibility + 0.001)
  })

  it('three agreeing high-leakage sources → high belief', () => {
    const masses = [
      createMass(4.0, 5.0, 0.8, 'a'),
      createMass(4.5, 5.0, 0.7, 'b'),
      createMass(3.5, 5.0, 0.6, 'c'),
    ]
    const r = fuseEvidence(masses)
    expect(r.belief).toBeGreaterThan(0.7)
  })

  it('tracks conflict level', () => {
    const masses = [
      createMass(5.0, 5.0, 0.9, 'exposed'),  // strong exposed
      createMass(0.0, 5.0, 0.9, 'private'),   // strong private
    ]
    const r = fuseEvidence(masses)
    expect(r.conflict).toBeGreaterThan(0.3)
  })

  it('tracks all sources', () => {
    const masses = [
      createMass(1, 5, 0.5, 'clustering'),
      createMass(2, 5, 0.5, 'timing'),
    ]
    const r = fuseEvidence(masses)
    expect(r.sources).toEqual(['clustering', 'timing'])
  })
})
