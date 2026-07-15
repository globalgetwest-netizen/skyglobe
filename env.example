import type { Metadata } from 'next'
import Employment from '@/components/sections/Employment'
import CTA from '@/components/sections/CTA'
import Container from '@/components/layout/Container'
import { Check } from 'lucide-react'

export const metadata: Metadata = {
  title: 'EU Employment | SkyGlobe Group',
  description: 'Direct EU employment placement with full visa and relocation support.',
}

const sectors = [
  { name: 'Healthcare & Nursing', openings: '340+ roles' },
  { name: 'Engineering & Tech', openings: '280+ roles' },
  { name: 'Hospitality & Tourism', openings: '500+ roles' },
  { name: 'Construction & Trades', openings: '420+ roles' },
  { name: 'Agriculture & Food', openings: '190+ roles' },
  { name: 'Education & Teaching', openings: '150+ roles' },
]

const steps = [
  { step: '01', title: 'Apply Online', desc: 'Submit your CV and preferred sector via our online form.' },
  { step: '02', title: 'Profile Assessment', desc: 'Our team reviews your qualifications and matches you with EU employers.' },
  { step: '03', title: 'Interview & Offer', desc: 'Attend employer interviews and receive your job offer.' },
  { step: '04', title: 'Visa & Documents', desc: 'We process your work visa and all required documentation.' },
  { step: '05', title: 'Relocation', desc: 'Travel to your new country with our pre-departure support.' },
  { step: '06', title: 'Settle In', desc: 'On-ground support helps you integrate and thrive in your new role.' },
]

export default function EUEmploymentPage() {
  return (
    <>
      <section className="bg-[#1A3A8F] py-20">
        <Container>
          <div className="max-w-2xl mx-auto text-center">
            <span className="inline-block px-4 py-1.5 rounded-full bg-white/15 text-white text-sm font-semibold mb-6">
              EU Employment Programme
            </span>
            <h1 className="text-[48px] leading-[56px] font-extrabold text-white mb-5">
              Work & Thrive Across Europe
            </h1>
            <p className="text-white/80 text-[16px] leading-[28px]">
              Secure a verified job in the EU with full documentation, visa, and relocation
              support — all managed by SkyGlobe Group.
            </p>
          </div>
        </Container>
      </section>

      <Employment />

      {/* Sectors */}
      <section className="bg-white py-20">
        <Container>
          <div className="text-center mb-12">
            <h2 className="text-[28px] leading-[36px] font-extrabold text-[#202124] mb-3">
              Active Sectors
            </h2>
            <p className="text-[#5F6368] text-sm">We have live vacancies across these high-demand fields.</p>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            {sectors.map(({ name, openings }) => (
              <div key={name} className="bg-[#F8F9FA] rounded-[24px] p-6 flex items-center gap-4">
                <Check size={18} className="text-[#1A3A8F] flex-shrink-0" />
                <div>
                  <p className="font-semibold text-[#202124] text-sm">{name}</p>
                  <p className="text-xs text-[#5F6368] mt-0.5">{openings}</p>
                </div>
              </div>
            ))}
          </div>
        </Container>
      </section>

      {/* Process */}
      <section className="bg-[#F8F9FA] py-20">
        <Container>
          <div className="text-center mb-12">
            <h2 className="text-[28px] leading-[36px] font-extrabold text-[#202124] mb-3">
              How It Works
            </h2>
          </div>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {steps.map(({ step, title, desc }) => (
              <div key={step} className="bg-white rounded-[24px] p-6 shadow-[0_1px_3px_rgba(60,64,67,0.10)]">
                <span className="text-4xl font-extrabold text-[#1A3A8F]/15">{step}</span>
                <h3 className="font-bold text-[#202124] mt-2 mb-2">{title}</h3>
                <p className="text-sm text-[#5F6368] leading-[22px]">{desc}</p>
              </div>
            ))}
          </div>
        </Container>
      </section>

      <CTA />
    </>
  )
}
