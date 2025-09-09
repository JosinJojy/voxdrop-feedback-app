"use client";

import { motion } from "framer-motion";

const AnimateText = ({ children, className, isHeading }: { children: React.ReactNode, className: string, isHeading?: boolean }) => {
  return (
    <motion.h1
      initial={{ opacity: 0, y: 10 }}
      whileInView={{ opacity: 1, y: 0 }}
      transition={{ duration: isHeading ? 0.4 : 0.6, ease: "easeOut" }}
      viewport={{ once: true, amount: 1 }}   
      className={className}
    >
      {children}
    </motion.h1>
  );
};

export default AnimateText;
