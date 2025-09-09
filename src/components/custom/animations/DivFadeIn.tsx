"use client";

import { motion } from "framer-motion";

export default function DivFadeIn({ children, className, initial, viewport }: { children: React.ReactNode, className?: string, initial?: number, viewport?:  number}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: initial ? initial : 20}}       
      whileInView={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, ease: "easeOut" }}
      viewport={{ once: true, amount: viewport ? viewport : 0.9 }}  
      className={className ? className : ""}
    >
      {children}
    </motion.div>
  );
}
