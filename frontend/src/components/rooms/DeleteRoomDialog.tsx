import { Dialog, Transition } from '@headlessui/react'
import { Fragment } from 'react'
import { ExclamationTriangleIcon } from '@heroicons/react/24/outline'

// 1. Les paramètres attendus par la modale
interface DeleteRoomDialogProps {
    isOpen: boolean;         // true = ouverte, false = fermée
    onClose: () => void;     // Fonction à appeler quand on annule (ferme la modale)
    onConfirm: () => void;   // Fonction à appeler quand on confirme la suppression
    roomNumber: string;      // Le numéro de la chambre pour l'affichage (ex: "101")
}

export function DeleteRoomDialog({ isOpen, onClose, onConfirm, roomNumber }: DeleteRoomDialogProps) {
    return (
        // Transition gère les animations d'apparition/disparition (fade-in)
        <Transition appear show={isOpen} as={Fragment}>
            <Dialog as="div" className="relative z-10" onClose={onClose}>

                {/* Le fond noir semi-transparent */}
                <Transition.Child
                    as={Fragment}
                    enter="ease-out duration-300"
                    enterFrom="opacity-0"
                    enterTo="opacity-100"
                    leave="ease-in duration-200"
                    leaveFrom="opacity-100"
                    leaveTo="opacity-0"
                >
                    <div className="fixed inset-0 bg-black/25" />
                </Transition.Child>

                {/* Le conteneur central pour positionner la boîte au milieu de l'écran */}
                <div className="fixed inset-0 overflow-y-auto">
                    <div className="flex min-h-full items-center justify-center p-4 text-center">
                        <Transition.Child
                            as={Fragment}
                            enter="ease-out duration-300"
                            enterFrom="opacity-0 scale-95"
                            enterTo="opacity-100 scale-100"
                            leave="ease-in duration-200"
                            leaveFrom="opacity-100 scale-100"
                            leaveTo="opacity-0 scale-95"
                        >
                            {/* La vraie boîte blanche de la modale */}
                            <Dialog.Panel className="w-full max-w-md transform overflow-hidden rounded-2xl bg-white p-6 text-left align-middle shadow-xl transition-all">

                                <div className="flex items-center gap-4">
                                    <div className="flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-full bg-red-100 sm:mx-0 sm:h-10 sm:w-10">
                                        <ExclamationTriangleIcon className="h-6 w-6 text-red-600" aria-hidden="true" />
                                    </div>
                                    <Dialog.Title as="h3" className="text-lg font-medium leading-6 text-zinc-900">
                                        Supprimer la chambre {roomNumber}
                                    </Dialog.Title>
                                </div>

                                <div className="mt-2">
                                    <p className="text-sm text-zinc-500">
                                        Êtes-vous sûr de vouloir supprimer cette chambre ? Cette action est irréversible et retirera la chambre de l'inventaire.
                                    </p>
                                </div>

                                {/* Les boutons d'action */}
                                <div className="mt-6 flex justify-end gap-3">
                                    <button
                                        type="button"
                                        className="inline-flex justify-center rounded-md border border-zinc-200 bg-white px-4 py-2 text-sm font-medium text-zinc-900 hover:bg-zinc-50"
                                        onClick={onClose} // Appelle la fonction lambda d'annulation
                                    >
                                        Annuler
                                    </button>
                                    <button
                                        type="button"
                                        className="inline-flex justify-center rounded-md border border-transparent bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 focus:outline-none"
                                        onClick={onConfirm} // Appelle la fonction lambda de confirmation
                                    >
                                        Oui, supprimer
                                    </button>
                                </div>
                            </Dialog.Panel>
                        </Transition.Child>
                    </div>
                </div>
            </Dialog>
        </Transition>
    )
}
