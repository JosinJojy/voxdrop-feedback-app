import { Loader2 } from "lucide-react"

const Loading = () => {
  return (
    <div className="flex items-center justify-center w-full h-screen">
      <Loader2 className="text-primary w-24 h-24 animate-spin transition duration-50"/>
    </div>
  )
}

export default Loading
