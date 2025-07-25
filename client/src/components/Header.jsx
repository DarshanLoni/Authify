import React from 'react'
import { assets } from '../assets/assets'

const Header = () => {
  return (
    <div className='flex flex-col items-center mt-20 px-4 text-center text-gray-800'>
        <img src={assets.header_img} alt="" className='w-36 h-36 rounder-full mb-6'/>
        <h1>Hey Developer <img src={assets.hand_wave} alt="" className='w-8 aspect-square'/></h1>
        <h2>Welcome to Authify</h2>
        <p>Lets start with a product tour we will have you up and running in no time</p>
        <button>Get Started</button>
    </div>
  )
}

export default Header