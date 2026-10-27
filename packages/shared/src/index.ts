export enum TaskStatus {
  TODO = 'TODO',
  DOING = 'DOING',
  DONE = 'DONE',
}

export interface ITask {
  id: string
  title: string
  description: string
  status: TaskStatus
}

